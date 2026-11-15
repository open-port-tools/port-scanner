use crate::engine::{
    export_report, ip_sort_key, render_report_csv, render_report_json, run_scan, PortResult,
    ScanConfig, ScanEvent, ScanProgress, ScanReport,
};
use crate::services::{detect_local_networks, parse_ports, parse_targets, LocalNetInfo, PROFILES};
use eframe::egui::{
    self, Align, Color32, Context, FontData, FontDefinitions, FontFamily, Frame, Key, Layout,
    Margin, RichText, Rounding, ScrollArea, Sense, Stroke, TextEdit, Vec2,
};
use std::cmp::Ordering as CmpOrdering;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

const BG_DARK: Color32 = Color32::from_rgb(0x11, 0x12, 0x14);
const SURFACE: Color32 = Color32::from_rgb(0x18, 0x1a, 0x1f);
const SURFACE_ALT: Color32 = Color32::from_rgb(0x1d, 0x20, 0x26);
const BORDER: Color32 = Color32::from_rgb(0x27, 0x2a, 0x31);
const TEXT_PRIMARY: Color32 = Color32::from_rgb(0xe6, 0xe8, 0xec);
const TEXT_MUTED: Color32 = Color32::from_rgb(0x8b, 0x92, 0xa1);
const ACCENT: Color32 = Color32::from_rgb(0x25, 0x63, 0xeb);
const ACCENT_SOFT: Color32 = Color32::from_rgb(0x1e, 0x3a, 0x5f);
const DANGER: Color32 = Color32::from_rgb(0xb9, 0x1c, 0x1c);
const OPEN_GREEN: Color32 = Color32::from_rgb(0x34, 0xd3, 0x99);
const OPEN_GREEN_BG: Color32 = Color32::from_rgb(0x12, 0x2b, 0x22);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresetChoice {
    Profile(usize),
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Ip,
    Port,
    Service,
    Latency,
    Banner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SortState {
    column: SortColumn,
    ascending: bool,
}

enum UiAsyncMsg {
    LanDetected(LocalNetInfo),
    Scan(ScanEvent),
}

struct PortScannerApp {
    rt: Arc<tokio::runtime::Runtime>,
    target_input: String,
    lan_info: Option<LocalNetInfo>,
    lan_detecting: bool,
    preset: PresetChoice,
    custom_ports_input: String,
    timeout_secs: f64,
    concurrency: usize,

    scanning: bool,
    has_scanned_once: bool,
    cancel_flag: Option<Arc<AtomicBool>>,
    async_rx: Option<mpsc::UnboundedReceiver<UiAsyncMsg>>,
    async_tx: mpsc::UnboundedSender<UiAsyncMsg>,

    progress: Option<ScanProgress>,
    last_report: Option<ScanReport>,
    results: Vec<PortResult>,
    status_text: String,
    status_is_error: bool,

    filter_query: String,
    sort: SortState,
}

impl PortScannerApp {
    fn new(cc: &eframe::CreationContext<'_>, initial_target: Option<String>) -> Self {
        install_system_fonts(&cc.egui_ctx);
        apply_theme(&cc.egui_ctx);

        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to initialize Tokio runtime"),
        );

        let (async_tx, async_rx) = mpsc::unbounded_channel();

        // Detect LAN subnet asynchronously so GUI opens immediately.
        let tx_lan = async_tx.clone();
        let ctx_lan = cc.egui_ctx.clone();
        rt.spawn_blocking(move || {
            let info = detect_local_networks();
            let _ = tx_lan.send(UiAsyncMsg::LanDetected(info));
            ctx_lan.request_repaint();
        });

        let target_input = initial_target.unwrap_or_else(|| "127.0.0.1".to_string());

        Self {
            rt,
            target_input,
            lan_info: None,
            lan_detecting: true,
            preset: PresetChoice::Profile(0), // Быстрый (25)
            custom_ports_input: "22,80,443,3000,5432,8080".to_string(),
            timeout_secs: 0.75,
            concurrency: 350,

            scanning: false,
            has_scanned_once: false,
            cancel_flag: None,
            async_rx: Some(async_rx),
            async_tx,

            progress: None,
            last_report: None,
            results: Vec::new(),
            status_text: "Готово к сканированию".to_string(),
            status_is_error: false,

            filter_query: String::new(),
            sort: SortState {
                column: SortColumn::Ip,
                ascending: true,
            },
        }
    }

    fn start_scan(&mut self, ctx: &Context) {
        if self.scanning {
            return;
        }

        let target_raw = self.target_input.trim().to_string();
        if target_raw.is_empty() {
            self.status_text = "Укажите IP, хост или CIDR".to_string();
            self.status_is_error = true;
            return;
        }

        let targets = match parse_targets(&target_raw) {
            Ok(t) => t,
            Err(err) => {
                self.status_text = err;
                self.status_is_error = true;
                return;
            }
        };

        let ports = match self.preset {
            PresetChoice::Profile(idx) => {
                let profile = PROFILES.get(idx).map(|p| p.id).unwrap_or("quick");
                parse_ports(None, profile)
            }
            PresetChoice::Custom => parse_ports(Some(&self.custom_ports_input), "quick"),
        };

        let ports = match ports {
            Ok(p) => p,
            Err(err) => {
                self.status_text = err;
                self.status_is_error = true;
                return;
            }
        };

        let total_probes = targets.len() * ports.len();
        let config = ScanConfig {
            targets,
            ports,
            timeout_secs: self.timeout_secs,
            concurrency: self.concurrency,
            grab_banner: true,
            include_closed: false,
            include_filtered: false,
        };

        let cancel_flag = Arc::new(AtomicBool::new(false));
        self.cancel_flag = Some(Arc::clone(&cancel_flag));
        self.scanning = true;
        self.has_scanned_once = true;
        self.results.clear();
        self.last_report = None;
        self.status_is_error = false;
        self.progress = Some(ScanProgress {
            scanned: 0,
            total: total_probes,
            open_count: 0,
            closed_count: 0,
            filtered_count: 0,
            elapsed_secs: 0.0,
            rate: 0.0,
            cancelled: false,
        });
        self.status_text = format!(
            "Запуск: {} хост(ов) × {} порт(ов) ({} проверок)...",
            config.targets.len(),
            config.ports.len(),
            total_probes
        );

        let (scan_tx, mut scan_rx) = mpsc::unbounded_channel();
        let ui_tx = self.async_tx.clone();
        let ui_ctx = ctx.clone();

        self.rt.spawn(async move {
            while let Some(ev) = scan_rx.recv().await {
                if ui_tx.send(UiAsyncMsg::Scan(ev)).is_err() {
                    break;
                }
                ui_ctx.request_repaint();
            }
        });

        self.rt.spawn(async move {
            let _ = run_scan(config, cancel_flag, Some(scan_tx)).await;
        });
    }

    fn stop_scan(&mut self) {
        if let Some(flag) = &self.cancel_flag {
            flag.store(true, Ordering::Relaxed);
            self.status_text = "Остановка сканирования...".to_string();
        }
    }

    fn drain_messages(&mut self) {
        let Some(mut rx) = self.async_rx.take() else {
            return;
        };

        let mut need_sort = false;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                UiAsyncMsg::LanDetected(info) => {
                    self.lan_detecting = false;
                    self.lan_info = Some(info);
                }
                UiAsyncMsg::Scan(event) => match event {
                    ScanEvent::Finding(row) => {
                        self.results.push(row);
                        need_sort = true;
                    }
                    ScanEvent::Progress(p) => {
                        self.status_text = if p.cancelled {
                            format!("Остановка... {} / {}", p.scanned, p.total)
                        } else {
                            format!(
                                "Сканирование: {} / {} · открыто {} · {:.0} порт/с",
                                p.scanned, p.total, p.open_count, p.rate
                            )
                        };
                        self.progress = Some(p);
                    }
                    ScanEvent::Completed(report) => {
                        self.scanning = false;
                        self.cancel_flag = None;
                        self.status_is_error = false;
                        self.status_text = if report.cancelled {
                            format!(
                                "Остановлено · проверено {} · открыто {} · {:.2}с",
                                report.total_ports_scanned, report.open_count, report.duration_secs
                            )
                        } else {
                            format!(
                                "Завершено за {:.2}с · проверено {} · открыто {}",
                                report.duration_secs, report.total_ports_scanned, report.open_count
                            )
                        };
                        self.results = report.results.clone();
                        self.last_report = Some(report);
                        need_sort = true;
                    }
                    ScanEvent::Error(err) => {
                        self.scanning = false;
                        self.cancel_flag = None;
                        self.status_is_error = true;
                        self.status_text = err;
                    }
                },
            }
        }

        if need_sort {
            self.sort_results();
        }

        self.async_rx = Some(rx);
    }

    fn sort_results(&mut self) {
        let col = self.sort.column;
        let asc = self.sort.ascending;
        self.results.sort_by(|a, b| {
            let ord = match col {
                SortColumn::Ip => ip_sort_key(&a.ip)
                    .cmp(&ip_sort_key(&b.ip))
                    .then_with(|| a.port.cmp(&b.port)),
                SortColumn::Port => a
                    .port
                    .cmp(&b.port)
                    .then_with(|| ip_sort_key(&a.ip).cmp(&ip_sort_key(&b.ip))),
                SortColumn::Service => a
                    .service
                    .to_ascii_lowercase()
                    .cmp(&b.service.to_ascii_lowercase())
                    .then_with(|| a.port.cmp(&b.port)),
                SortColumn::Latency => {
                    let la = a.latency_ms.unwrap_or(f64::MAX);
                    let lb = b.latency_ms.unwrap_or(f64::MAX);
                    la.partial_cmp(&lb).unwrap_or(CmpOrdering::Equal)
                }
                SortColumn::Banner => a
                    .banner
                    .to_ascii_lowercase()
                    .cmp(&b.banner.to_ascii_lowercase()),
            };
            if asc {
                ord
            } else {
                ord.reverse()
            }
        });
    }

    fn current_snapshot_report(&self) -> ScanReport {
        if let Some(ref rep) = self.last_report {
            return rep.clone();
        }
        ScanReport {
            targets: vec![self.target_input.clone()],
            resolved_targets: Default::default(),
            total_ports_scanned: self.progress.as_ref().map(|p| p.scanned).unwrap_or(0),
            duration_secs: self.progress.as_ref().map(|p| p.elapsed_secs).unwrap_or(0.0),
            open_count: self.results.len(),
            closed_count: self.progress.as_ref().map(|p| p.closed_count).unwrap_or(0),
            filtered_count: self.progress.as_ref().map(|p| p.filtered_count).unwrap_or(0),
            cancelled: false,
            results: self.results.clone(),
        }
    }

    fn save_export(&mut self, ext: &str, ctx: &Context) {
        let report = self.current_snapshot_report();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dir = export_base_dir();
        let path = dir.join(format!("port-scan-{ts}.{ext}"));

        match export_report(&report, &path) {
            Ok(()) => {
                // Also copy contents to clipboard for quick pasting.
                let clipboard_text = if ext == "csv" {
                    render_report_csv(&report)
                } else {
                    render_report_json(&report).unwrap_or_default()
                };
                ctx.copy_text(clipboard_text);
                self.status_is_error = false;
                self.status_text = format!(
                    "Сохранено в {} (и скопировано в буфер)",
                    path.display()
                );
            }
            Err(err) => {
                self.status_is_error = true;
                self.status_text = err;
            }
        }
    }

    fn render_sort_header(&mut self, ui: &mut egui::Ui, label: &str, col: SortColumn) {
        let is_active = self.sort.column == col;
        let suffix = if is_active {
            if self.sort.ascending {
                " ↑"
            } else {
                " ↓"
            }
        } else {
            ""
        };
        let text = RichText::new(format!("{label}{suffix}"))
            .size(12.0)
            .color(if is_active { TEXT_PRIMARY } else { TEXT_MUTED })
            .strong();
        if ui
            .add(egui::Button::new(text).frame(false).sense(Sense::click()))
            .clicked()
        {
            if self.sort.column == col {
                self.sort.ascending = !self.sort.ascending;
            } else {
                self.sort.column = col;
                self.sort.ascending = true;
            }
            self.sort_results();
        }
    }
}

impl eframe::App for PortScannerApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.drain_messages();

        egui::CentralPanel::default()
            .frame(Frame::none().fill(BG_DARK).inner_margin(Margin::same(16.0)))
            .show(ctx, |ui| {
                // Top control bar inside flat bordered surface
                Frame::none()
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, BORDER))
                    .rounding(Rounding::same(8.0))
                    .inner_margin(Margin::symmetric(12.0, 10.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;

                            // 1-click Localhost vs Entire LAN segmented buttons
                            let is_localhost = self.target_input.trim() == "127.0.0.1";
                            let lan_cidr = self
                                .lan_info
                                .as_ref()
                                .map(|i| i.cidr.clone())
                                .unwrap_or_default();
                            let is_lan = !lan_cidr.is_empty()
                                && (self.target_input.trim() == lan_cidr
                                    || self.target_input.trim().eq_ignore_ascii_case("lan"));

                            let local_btn = egui::Button::new(
                                RichText::new("Этот ПК").size(13.0).color(if is_localhost {
                                    Color32::WHITE
                                } else {
                                    TEXT_PRIMARY
                                }),
                            )
                            .fill(if is_localhost { ACCENT_SOFT } else { SURFACE_ALT })
                            .stroke(Stroke::new(1.0, if is_localhost { ACCENT } else { BORDER }))
                            .rounding(Rounding::same(6.0))
                            .min_size(Vec2::new(78.0, 30.0));

                            if ui.add(local_btn).clicked() && !self.scanning {
                                self.target_input = "127.0.0.1".to_string();
                            }

                            let (lan_label, lan_enabled, lan_tip) = match &self.lan_info {
                                Some(info) if !info.cidr.is_empty() => (
                                    format!("Вся сеть · {}", info.cidr),
                                    true,
                                    format!(
                                        "Локальный IP: {} · {} хостов",
                                        info.primary_ip, info.host_count
                                    ),
                                ),
                                _ if self.lan_detecting => (
                                    "Вся сеть · поиск...".to_string(),
                                    false,
                                    "Определение локальной подсети".to_string(),
                                ),
                                _ => (
                                    "Вся сеть · н/д".to_string(),
                                    false,
                                    "Локальная IPv4 сеть не обнаружена".to_string(),
                                ),
                            };

                            let lan_btn = egui::Button::new(
                                RichText::new(lan_label).size(13.0).color(if is_lan {
                                    Color32::WHITE
                                } else if lan_enabled {
                                    TEXT_PRIMARY
                                } else {
                                    TEXT_MUTED
                                }),
                            )
                            .fill(if is_lan { ACCENT_SOFT } else { SURFACE_ALT })
                            .stroke(Stroke::new(1.0, if is_lan { ACCENT } else { BORDER }))
                            .rounding(Rounding::same(6.0))
                            .min_size(Vec2::new(130.0, 30.0));

                            let lan_resp = ui.add_enabled(lan_enabled && !self.scanning, lan_btn);
                            if lan_resp.clicked() && !lan_cidr.is_empty() {
                                self.target_input = lan_cidr;
                            }
                            lan_resp.on_hover_text(lan_tip);

                            // Preset selector + Scan CTA on right, target input fills remaining space
                            let right_reserve = 280.0;
                            let target_width = (ui.available_width() - right_reserve).max(160.0);

                            let edit_resp = ui.add_enabled(
                                !self.scanning,
                                TextEdit::singleline(&mut self.target_input)
                                    .hint_text("IP, хост, 192.168.0.0/24 или lan")
                                    .desired_width(target_width)
                                    .margin(Margin::symmetric(8.0, 6.0)),
                            );
                            if edit_resp.lost_focus()
                                && ui.input(|i| i.key_pressed(Key::Enter))
                                && !self.scanning
                            {
                                self.start_scan(ctx);
                            }

                            let selected_label = match self.preset {
                                PresetChoice::Profile(idx) => PROFILES
                                    .get(idx)
                                    .map(|p| p.label)
                                    .unwrap_or("Быстрый (25)"),
                                PresetChoice::Custom => "Свои порты...",
                            };

                            ui.add_enabled_ui(!self.scanning, |ui| {
                                egui::ComboBox::from_id_salt("preset_combo")
                                    .selected_text(selected_label)
                                    .width(155.0)
                                    .show_ui(ui, |ui| {
                                        for (idx, p) in PROFILES.iter().enumerate() {
                                            ui.selectable_value(
                                                &mut self.preset,
                                                PresetChoice::Profile(idx),
                                                p.label,
                                            );
                                        }
                                        ui.selectable_value(
                                            &mut self.preset,
                                            PresetChoice::Custom,
                                            "Свои порты...",
                                        );
                                    });
                            });

                            let cta_btn = if self.scanning {
                                egui::Button::new(
                                    RichText::new("Остановить")
                                        .size(13.0)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(DANGER)
                                .rounding(Rounding::same(6.0))
                                .min_size(Vec2::new(108.0, 30.0))
                            } else {
                                egui::Button::new(
                                    RichText::new("Сканировать")
                                        .size(13.0)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(ACCENT)
                                .rounding(Rounding::same(6.0))
                                .min_size(Vec2::new(108.0, 30.0))
                            };

                            if ui.add(cta_btn).clicked() {
                                if self.scanning {
                                    self.stop_scan();
                                } else {
                                    self.start_scan(ctx);
                                }
                            }
                        });

                        // Conditional custom port / tuning row only when "Свои порты..." selected
                        if matches!(self.preset, PresetChoice::Custom) {
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("Порты:").size(12.0).color(TEXT_MUTED),
                                );
                                ui.add_enabled(
                                    !self.scanning,
                                    TextEdit::singleline(&mut self.custom_ports_input)
                                        .hint_text("22,80,443,8000-8080 или all")
                                        .desired_width(260.0)
                                        .margin(Margin::symmetric(8.0, 4.0)),
                                );
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new("Таймаут (с):").size(12.0).color(TEXT_MUTED),
                                );
                                ui.add_enabled(
                                    !self.scanning,
                                    egui::DragValue::new(&mut self.timeout_secs)
                                        .range(0.1..=10.0)
                                        .speed(0.05)
                                        .fixed_decimals(2),
                                );
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new("Потоки:").size(12.0).color(TEXT_MUTED),
                                );
                                ui.add_enabled(
                                    !self.scanning,
                                    egui::DragValue::new(&mut self.concurrency)
                                        .range(10..=1500)
                                        .speed(10.0),
                                );
                            });
                        }
                    });

                ui.add_space(10.0);

                // Slim progress bar (only while active or after progress exists)
                if let Some(ref prog) = self.progress {
                    if self.scanning || prog.scanned > 0 {
                        let ratio = if prog.total > 0 {
                            (prog.scanned as f32 / prog.total as f32).clamp(0.0, 1.0)
                        } else {
                            0.0
                        };
                        let bar = egui::ProgressBar::new(ratio)
                            .desired_height(3.0)
                            .fill(if self.scanning { ACCENT } else { OPEN_GREEN });
                        ui.add(bar);
                        ui.add_space(6.0);
                    }
                }

                // Status + conditional Filter / CSV / JSON bar
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&self.status_text)
                            .size(12.5)
                            .color(if self.status_is_error {
                                Color32::from_rgb(0xf8, 0x71, 0x71)
                            } else {
                                TEXT_MUTED
                            }),
                    );

                    if !self.results.is_empty() {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;

                            let json_btn = egui::Button::new(
                                RichText::new("JSON").size(12.0).color(TEXT_PRIMARY),
                            )
                            .fill(SURFACE_ALT)
                            .stroke(Stroke::new(1.0, BORDER))
                            .rounding(Rounding::same(5.0));
                            if ui.add(json_btn).clicked() {
                                self.save_export("json", ctx);
                            }

                            let csv_btn = egui::Button::new(
                                RichText::new("CSV").size(12.0).color(TEXT_PRIMARY),
                            )
                            .fill(SURFACE_ALT)
                            .stroke(Stroke::new(1.0, BORDER))
                            .rounding(Rounding::same(5.0));
                            if ui.add(csv_btn).clicked() {
                                self.save_export("csv", ctx);
                            }

                            ui.add(
                                TextEdit::singleline(&mut self.filter_query)
                                    .hint_text("Фильтр...")
                                    .desired_width(170.0)
                                    .margin(Margin::symmetric(8.0, 4.0)),
                            );
                        });
                    }
                });

                ui.add_space(8.0);

                // Main results area
                Frame::none()
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, BORDER))
                    .rounding(Rounding::same(8.0))
                    .show(ui, |ui| {
                        let needle = self.filter_query.trim().to_ascii_lowercase();
                        let filtered_indices: Vec<usize> = self
                            .results
                            .iter()
                            .enumerate()
                            .filter(|(_, r)| {
                                if needle.is_empty() {
                                    return true;
                                }
                                r.ip.to_ascii_lowercase().contains(&needle)
                                    || r.target.to_ascii_lowercase().contains(&needle)
                                    || r.port.to_string().contains(&needle)
                                    || r.service.to_ascii_lowercase().contains(&needle)
                                    || r.banner.to_ascii_lowercase().contains(&needle)
                            })
                            .map(|(idx, _)| idx)
                            .collect();

                        if self.results.is_empty() {
                            let avail = ui.available_size();
                            ui.allocate_ui_with_layout(
                                avail,
                                Layout::centered_and_justified(egui::Direction::TopDown),
                                |ui| {
                                    let msg = if self.scanning {
                                        "Идёт асинхронное сканирование..."
                                    } else if self.has_scanned_once {
                                        "Открытых портов не обнаружено"
                                    } else {
                                        "Выберите «Этот ПК», «Вся сеть» или введите цель и нажмите «Сканировать»"
                                    };
                                    ui.label(RichText::new(msg).size(13.5).color(TEXT_MUTED));
                                },
                            );
                            return;
                        }

                        // Table header
                        let total_w = ui.available_width();
                        let col_ip = 175.0_f32;
                        let col_port = 74.0_f32;
                        let col_service = 140.0_f32;
                        let col_lat = 86.0_f32;
                        let col_banner = (total_w - col_ip - col_port - col_service - col_lat - 48.0).max(120.0);

                        Frame::none()
                            .fill(SURFACE_ALT)
                            .inner_margin(Margin::symmetric(12.0, 8.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.allocate_ui(Vec2::new(col_ip, 18.0), |ui| {
                                        self.render_sort_header(ui, "IP / Хост", SortColumn::Ip);
                                    });
                                    ui.allocate_ui(Vec2::new(col_port, 18.0), |ui| {
                                        self.render_sort_header(ui, "Порт", SortColumn::Port);
                                    });
                                    ui.allocate_ui(Vec2::new(col_service, 18.0), |ui| {
                                        self.render_sort_header(ui, "Сервис", SortColumn::Service);
                                    });
                                    ui.allocate_ui(Vec2::new(col_lat, 18.0), |ui| {
                                        self.render_sort_header(ui, "Задержка", SortColumn::Latency);
                                    });
                                    ui.allocate_ui(Vec2::new(col_banner, 18.0), |ui| {
                                        self.render_sort_header(ui, "Баннер", SortColumn::Banner);
                                    });
                                });
                            });

                        ui.separator();

                        ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                for (vis_i, &idx) in filtered_indices.iter().enumerate() {
                                    let row = &self.results[idx];
                                    let bg = if vis_i % 2 == 1 {
                                        Color32::from_rgb(0x15, 0x17, 0x1c)
                                    } else {
                                        SURFACE
                                    };
                                    let row_resp = Frame::none()
                                        .fill(bg)
                                        .inner_margin(Margin::symmetric(12.0, 7.0))
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                let host_display = if row.target != row.ip {
                                                    format!("{} ({})", row.ip, row.target)
                                                } else {
                                                    row.ip.clone()
                                                };
                                                ui.allocate_ui(Vec2::new(col_ip, 20.0), |ui| {
                                                    ui.add(
                                                        egui::Label::new(
                                                            RichText::new(host_display)
                                                                .monospace()
                                                                .size(12.5)
                                                                .color(TEXT_PRIMARY),
                                                        )
                                                        .truncate(),
                                                    );
                                                });

                                                ui.allocate_ui(Vec2::new(col_port, 20.0), |ui| {
                                                    Frame::none()
                                                        .fill(OPEN_GREEN_BG)
                                                        .rounding(Rounding::same(4.0))
                                                        .inner_margin(Margin::symmetric(6.0, 2.0))
                                                        .show(ui, |ui| {
                                                            ui.label(
                                                                RichText::new(format!(
                                                                    "{}",
                                                                    row.port
                                                                ))
                                                                .monospace()
                                                                .size(12.0)
                                                                .strong()
                                                                .color(OPEN_GREEN),
                                                            );
                                                        });
                                                });

                                                ui.allocate_ui(Vec2::new(col_service, 20.0), |ui| {
                                                    ui.add(
                                                        egui::Label::new(
                                                            RichText::new(&row.service)
                                                                .size(12.5)
                                                                .color(TEXT_PRIMARY),
                                                        )
                                                        .truncate(),
                                                    );
                                                });

                                                ui.allocate_ui(Vec2::new(col_lat, 20.0), |ui| {
                                                    let lat = row
                                                        .latency_ms
                                                        .map(|ms| format!("{ms:.1} ms"))
                                                        .unwrap_or_else(|| "—".to_string());
                                                    ui.label(
                                                        RichText::new(lat)
                                                            .monospace()
                                                            .size(12.0)
                                                            .color(TEXT_MUTED),
                                                    );
                                                });

                                                ui.allocate_ui(Vec2::new(col_banner, 20.0), |ui| {
                                                    let banner_text = if row.banner.is_empty() {
                                                        "—"
                                                    } else {
                                                        &row.banner
                                                    };
                                                    ui.add(
                                                        egui::Label::new(
                                                            RichText::new(banner_text)
                                                                .size(12.0)
                                                                .color(TEXT_MUTED),
                                                        )
                                                        .truncate(),
                                                    );
                                                });
                                            });
                                        })
                                        .response;

                                    if !row.banner.is_empty() {
                                        row_resp.on_hover_text(&row.banner);
                                    }
                                }
                            });
                    });
            });
    }
}

fn export_base_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        let downloads = PathBuf::from(&home).join("Downloads");
        if downloads.is_dir() {
            return downloads;
        }
        let desktop = PathBuf::from(&home).join("Desktop");
        if desktop.is_dir() {
            return desktop;
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn install_system_fonts(ctx: &Context) {
    let mut fonts = FontDefinitions::default();

    let prop_candidates: &[&str] = &[
        // macOS
        "/System/Library/Fonts/SFNS.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
        // Windows
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\tahoma.ttf",
        // Linux
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
    ];

    for path in prop_candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("sys_sans".to_string(), FontData::from_owned(bytes));
            if let Some(fam) = fonts.families.get_mut(&FontFamily::Proportional) {
                fam.insert(0, "sys_sans".to_string());
            }
            break;
        }
    }

    let mono_candidates: &[&str] = &[
        "/System/Library/Fonts/SFNSMono.ttf",
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "C:\\Windows\\Fonts\\consola.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ];

    for path in mono_candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("sys_mono".to_string(), FontData::from_owned(bytes));
            if let Some(fam) = fonts.families.get_mut(&FontFamily::Monospace) {
                fam.insert(0, "sys_mono".to_string());
            }
            break;
        }
    }

    ctx.set_fonts(fonts);
}

fn apply_theme(ctx: &Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = BG_DARK;
    visuals.panel_fill = BG_DARK;
    visuals.extreme_bg_color = BG_DARK;
    visuals.faint_bg_color = SURFACE_ALT;
    visuals.widgets.noninteractive.bg_fill = SURFACE;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.inactive.bg_fill = SURFACE_ALT;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x24, 0x28, 0x30);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x3a, 0x3f, 0x4b));
    visuals.widgets.active.bg_fill = ACCENT_SOFT;
    visuals.selection.bg_fill = ACCENT;
    visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
    ctx.set_visuals(visuals);
}

/// Launch the native GPU GUI window (`eframe` + `egui`).
pub fn launch_gui(initial_target: Option<String>) -> Result<(), String> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Port Scanner")
            .with_inner_size([940.0, 620.0])
            .with_min_inner_size([720.0, 460.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Port Scanner",
        native_options,
        Box::new(|cc| Ok(Box::new(PortScannerApp::new(cc, initial_target)))),
    )
    .map_err(|e| format!("GUI startup error: {e}"))
}
