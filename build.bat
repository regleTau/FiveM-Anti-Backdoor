
@echo off
echo ===================================================
echo FiveM Anti-Backdoor - Compiling Standalone Executable
echo ===================================================
echo.

echo 1. Installing requirements...
pip install -r requirements.txt

echo.
echo 2. Running unit tests...
python -m unittest discover -s tests -p "test_*.py"
if %errorlevel% neq 0 (
    echo [ERROR] Unit tests failed. Aborting build.
    exit /b %errorlevel%
)

echo.
echo 3. Compiling executable with PyInstaller...
pyinstaller --clean --noconfirm fivem_antivirus.spec

echo.
echo ===================================================
echo Build completed! Standalone binary is located in dist/
echo ===================================================
pause
