@echo off
setlocal enabledelayedexpansion

REM Setup environment for standalone rAIversing
echo Starting environment setup...

REM Set IDA Pro directory
set "IDA_DIR=C:\Users\hnoue\Desktop\IDA Pro 8.3 2"
set "IDA_PYTHON_DIR=%IDA_DIR%\python\3"

echo Checking IDA installation...
if not exist "%IDA_DIR%" (
    echo ERROR: IDA directory not found: %IDA_DIR%
    exit /b 1
)

if not exist "%IDA_PYTHON_DIR%" (
    echo ERROR: IDA Python directory not found: %IDA_PYTHON_DIR%
    exit /b 1
)

REM Set Python path - Using exact path provided
set "PYTHON_DIR=C:\Users\hnoue\AppData\Local\Programs\Python\Python39-32"
set "PYTHON_SITE_PACKAGES=%PYTHON_DIR%\Lib\site-packages"

echo Checking Python installation...
if not exist "%PYTHON_DIR%\python.exe" (
    echo ERROR: 32-bit Python executable not found: %PYTHON_DIR%\python.exe
    echo Please install 32-bit Python 3.9 which is required for IDA Pro 8.3
    echo Download from: https://www.python.org/downloads/release/python-390/
    echo Select: Windows x86 executable installer
    exit /b 1
)

REM Check Python version and architecture
echo Checking Python version and architecture...
"%PYTHON_DIR%\python.exe" -c "import sys, platform; print(str(sys.version_info[0]) + '.' + str(sys.version_info[1])); print(platform.architecture()[0])" > "%TEMP%\pyver.txt"
set /p PYTHON_VERSION=<"%TEMP%\pyver.txt"
set /p PYTHON_ARCH=<"%TEMP%\pyver.txt"
del "%TEMP%\pyver.txt"

echo Found Python version: %PYTHON_VERSION%
echo Python architecture: %PYTHON_ARCH%

if not "%PYTHON_VERSION%"=="3.9" (
    echo ERROR: IDA Pro 8.3 requires Python 3.9
    echo Current Python version is %PYTHON_VERSION%
    echo Please install Python 3.9
    exit /b 1
)

if not "%PYTHON_ARCH%"=="32bit" (
    echo ERROR: IDA Pro requires 32-bit Python
    echo Current Python architecture is %PYTHON_ARCH%
    echo Please install 32-bit Python 3.9
    echo Download from: https://www.python.org/downloads/release/python-390/
    echo Select: Windows x86 executable installer
    exit /b 1
)

echo Using compatible Python version
echo.

REM Create a temporary directory for modules
set "TEMP_MODULES_DIR=%TEMP%\ida_python_modules"
echo Creating temporary directory: %TEMP_MODULES_DIR%
if exist "%TEMP_MODULES_DIR%" rd /s /q "%TEMP_MODULES_DIR%"
mkdir "%TEMP_MODULES_DIR%"

REM Copy Python modules and DLLs
echo Copying IDA Python modules...
echo Source: %IDA_PYTHON_DIR%
echo Destination: %TEMP_MODULES_DIR%

REM Copy with verbose output
echo Copying .py files...
for %%F in ("%IDA_PYTHON_DIR%\*.py") do (
    echo   %%~nxF
    copy "%%F" "%TEMP_MODULES_DIR%\" >nul
)

REM Copy Python extension modules from ida_32
echo Copying Python extension modules...
echo Copying 32-bit modules...
if not exist "%IDA_PYTHON_DIR%\ida_32" (
    echo ERROR: 32-bit IDA Python modules not found: %IDA_PYTHON_DIR%\ida_32
    exit /b 1
)
for %%F in ("%IDA_PYTHON_DIR%\ida_32\*.pyd") do (
    echo   %%~nxF
    copy "%%F" "%TEMP_MODULES_DIR%\" >nul
)

REM Copy required 32-bit DLLs from IDA directory
echo Copying IDA 32-bit DLLs...
set "REQUIRED_DLLS=ida.dll idapython3.dll"
for %%F in (%REQUIRED_DLLS%) do (
    if exist "%IDA_DIR%\%%F" (
        echo   %%F
        copy "%IDA_DIR%\%%F" "%TEMP_MODULES_DIR%\" >nul
    ) else (
        echo ERROR: Required DLL not found: %IDA_DIR%\%%F
        exit /b 1
    )
)

REM Copy Qt DLLs (32-bit only)
echo Copying Qt DLLs...
if exist "%IDA_DIR%\qt" (
    for %%F in ("%IDA_DIR%\qt\Qt5Core.dll" "%IDA_DIR%\qt\Qt5Gui.dll" "%IDA_DIR%\qt\Qt5Widgets.dll") do (
        if exist "%%F" (
            echo   %%~nxF
            copy "%%F" "%TEMP_MODULES_DIR%\" >nul
        )
    )
)

REM Create __init__.py if it doesn't exist
echo Creating __init__.py...
echo. > "%TEMP_MODULES_DIR%\__init__.py"

REM Set up Python environment
echo Setting up Python environment...
set "PYTHONPATH=%TEMP_MODULES_DIR%;%IDA_PYTHON_DIR%;%PYTHON_SITE_PACKAGES%;%PYTHONPATH%"
set "PATH=%TEMP_MODULES_DIR%;%IDA_DIR%;%PYTHON_DIR%;%PATH%"

REM Display environment information
echo.
echo Environment Setup:
echo -----------------
echo IDA Directory: %IDA_DIR%
echo IDA Python Directory: %IDA_PYTHON_DIR%
echo Python Directory: %PYTHON_DIR%
echo Temp Modules Directory: %TEMP_MODULES_DIR%
echo.
echo PYTHONPATH: %PYTHONPATH%
echo.

REM Check for IDA executable
if exist "%IDA_DIR%\ida.exe" (
    echo Found IDA executable: ida.exe
) else (
    echo ERROR: Could not find 32-bit IDA executable: %IDA_DIR%\ida.exe
    exit /b 1
)

REM List copied files
echo.
echo Files in temporary directory:
dir "%TEMP_MODULES_DIR%"

REM Copy test script
echo.
echo Copying test script...
copy "%~dp0test_imports.py" "%TEMP_MODULES_DIR%\" >nul

REM Run the test script
echo.
echo Testing Python module access...
cd /d "%TEMP_MODULES_DIR%" && "%PYTHON_DIR%\python.exe" "test_imports.py"
cd /d "%~dp0"

if not "%1"=="silent" (
    echo.
    echo Press any key to continue...
    pause > nul
)

REM Cleanup if there was an error
if errorlevel 1 (
    echo Environment setup failed
    echo Cleaning up temporary files...
    rd /s /q "%TEMP_MODULES_DIR%" 2>nul
    echo Cleanup complete.
    exit /b 1
)

endlocal 