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

REM Set Python path
set "PYTHON_DIR=C:\Users\hnoue\AppData\Local\Programs\Python\Python39"
set "PYTHON_SITE_PACKAGES=%PYTHON_DIR%\Lib\site-packages"

echo Checking Python installation...
if not exist "%PYTHON_DIR%\python.exe" (
    echo ERROR: Python executable not found: %PYTHON_DIR%\python.exe
    echo Please install Python 3.9 which is required for IDA Pro 8.3
    exit /b 1
)

REM Check Python version
echo Checking Python version...
"%PYTHON_DIR%\python.exe" -c "import sys; print(str(sys.version_info[0]) + '.' + str(sys.version_info[1]))" > "%TEMP%\pyver.txt"
set /p PYTHON_VERSION=<"%TEMP%\pyver.txt"
del "%TEMP%\pyver.txt"
echo Found Python version: %PYTHON_VERSION%
if not "%PYTHON_VERSION%"=="3.9" (
    echo ERROR: IDA Pro 8.3 requires Python 3.9
    echo Current Python version is %PYTHON_VERSION%
    echo Please install Python 3.9
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
for %%F in ("%IDA_PYTHON_DIR%\ida_32\*.pyd") do (
    echo   %%~nxF
    copy "%%F" "%TEMP_MODULES_DIR%\" >nul
)

echo Copying .dll files...
for %%F in ("%IDA_PYTHON_DIR%\*.dll") do (
    echo   %%~nxF
    copy "%%F" "%TEMP_MODULES_DIR%\" >nul
)

REM Copy additional IDA files (32-bit only)
echo Copying additional IDA files...
for %%F in (
    "%IDA_DIR%\ida.dll"
    "%IDA_DIR%\plugins\*.dll"
    "%IDA_DIR%\platforms\*.dll"
    "%IDA_DIR%\qt\*.dll"
) do (
    if not "%%~nxF"=="ida64.dll" (
        echo   %%~nxF
        copy "%%F" "%TEMP_MODULES_DIR%\" >nul 2>&1
    )
)

REM Create __init__.py if it doesn't exist
echo Creating __init__.py...
echo. > "%TEMP_MODULES_DIR%\__init__.py"

REM Set up Python environment
echo Setting up Python environment...
set "PYTHONPATH=%TEMP_MODULES_DIR%;%IDA_PYTHON_DIR%;%PYTHON_SITE_PACKAGES%;%PYTHONPATH%"
set "PATH=%IDA_DIR%;%TEMP_MODULES_DIR%;%PYTHON_DIR%;%PATH%"

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

REM Check for IDA executables
if exist "%IDA_DIR%\ida.exe" (
    set "IDA_EXE=%IDA_DIR%\ida.exe"
    echo Found IDA executable: ida.exe
) else (
    echo WARNING: Could not find 32-bit IDA executable
    echo Directory contents:
    dir "%IDA_DIR%\*.exe"
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