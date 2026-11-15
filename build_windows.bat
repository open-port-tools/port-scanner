@echo off
setlocal enabledelayedexpansion

echo === Async Port Scanner: Windows .exe Builder ===
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python 3.9+ was not found in PATH.
    echo Download Python from https://www.python.org/downloads/windows/ and check "Add python.exe to PATH".
    exit /b 1
)

if not exist ".venv-build" (
    python -m venv .venv-build
)
call .venv-build\Scripts\activate.bat

python -m pip install --upgrade pip
python -m pip install pyinstaller
python -m unittest discover -s tests -v
if errorlevel 1 (
    echo [ERROR] Unit tests failed. Aborting build.
    exit /b 1
)

python build_executable.py --mode all --clean-build
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)

echo.
echo Build succeeded!
echo   GUI Executable:     dist\PortScanner-GUI.exe
echo   Console Executable: dist\port-scanner.exe
endlocal
