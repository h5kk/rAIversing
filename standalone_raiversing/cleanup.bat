@echo off
REM Cleanup temporary files

set "TEMP_MODULES_DIR=%TEMP%\ida_python_modules"

if exist "%TEMP_MODULES_DIR%" (
    echo Cleaning up temporary files...
    rd /s /q "%TEMP_MODULES_DIR%"
    echo Cleanup complete.
) else (
    echo No temporary files found.
)

if not "%1"=="silent" pause 