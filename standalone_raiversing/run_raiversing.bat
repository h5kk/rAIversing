@echo off
REM Run rAIversing with environment setup

REM Clean up any existing temporary files
call cleanup.bat silent

REM Set up the environment (silent mode)
call setup_env.bat silent
if errorlevel 1 (
    echo Environment setup failed
    call cleanup.bat silent
    pause
    exit /b 1
)

REM Check if IDA executable was found
if "%IDA_EXE%"=="" (
    echo Error: Could not find IDA executable.
    echo Please make sure IDA Pro is installed correctly.
    call cleanup.bat silent
    pause
    exit /b 1
)

REM Check if command line mode is requested
if "%1"=="--cli" (
    REM Command line mode
    if "%~2"=="" (
        echo Usage: run_raiversing.bat --cli ^<path_to_idb^> ^<openai_api_key^>
        call cleanup.bat silent
        exit /b 1
    )

    if "%~3"=="" (
        echo Usage: run_raiversing.bat --cli ^<path_to_idb^> ^<openai_api_key^>
        call cleanup.bat silent
        exit /b 1
    )

    REM Run the Python script in CLI mode
    echo Running in CLI mode...
    echo Using Python: %PYTHON_DIR%\python.exe
    echo Using IDA: %IDA_EXE%
    echo IDB File: %~2
    echo.
    
    "%PYTHON_DIR%\python.exe" -E raiversing_core.py "%~2" "%~3"
) else (
    REM GUI mode
    echo Running in GUI mode...
    echo Using Python: %PYTHON_DIR%\python.exe
    echo Using IDA: %IDA_EXE%
    echo.
    
    "%PYTHON_DIR%\python.exe" -E raiversing_gui.py
)

REM Clean up temporary files
call cleanup.bat silent

pause 