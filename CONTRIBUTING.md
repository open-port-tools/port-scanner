# Contributing to Open Port Scanner

Thank you for considering contributing to **Open Port Scanner**! We welcome bug reports, feature requests, documentation improvements, and code contributions.

## Development Workflow

### Prerequisites
- [Rust 1.75+](https://www.rust-lang.org/tools/install) (`cargo`, `rustc`)
- Python 3.9+ (optional, for legacy tests)

### Setup & Local Build
```bash
git clone https://github.com/open-port-tools/port-scanner.git
cd port-scanner

# Build debug binary
cargo build

# Run native GUI
cargo run -- --gui

# Run CLI scanner
cargo run -- 127.0.0.1 --profile quick
```

### Running Tests
Before submitting a Pull Request, ensure all tests pass cleanly:
```bash
cargo test
python3 -m unittest discover -s tests -v
```

## Pull Request Guidelines
1. Fork the repository and create your branch from `main`.
2. Keep changes focused on a single bug fix or feature.
3. Write unit and integration tests for new functionality.
4. Ensure code passes `cargo clippy` and `cargo fmt`.
5. Submit a PR with a clear description of the problem and solution.
