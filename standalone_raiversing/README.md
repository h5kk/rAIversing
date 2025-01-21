# Standalone rAIversing

A standalone Python application for AI-powered reverse engineering using IDA Pro databases.

## Features

- Load and analyze IDB files without the IDA Pro GUI
- AI-powered function analysis using OpenAI GPT-4
- Automatic function renaming and documentation
- Multi-threaded analysis for better performance
- Periodic auto-saving of changes
- Progress tracking and detailed logging
- User-friendly GUI interface with settings management
- Command-line interface for automation

## Prerequisites

1. IDA Pro installation with IDAPython
2. Python 3.x
3. OpenAI API key

## Installation

### Windows

1. Install Python 3.12 from python.org if not already installed
2. Install the required Python packages:
   ```cmd
   pip install -r requirements.txt
   ```
3. Edit `setup_env.bat` if your IDA Pro or Python paths are different from:
   - IDA Pro: `C:\Users\hnoue\Desktop\IDA Pro 8.3 2`
   - Python: `C:\Users\hnoue\AppData\Local\Programs\Python\Python312`

### Linux/macOS

1. Make sure IDA Pro is installed and its Python directory is in your PYTHONPATH:
   ```bash
   export PYTHONPATH=/path/to/ida/python:$PYTHONPATH
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### GUI Mode (Recommended)

1. Run the application:
   ```cmd
   run_raiversing.bat
   ```

2. Use the GUI to:
   - Browse and select your IDB file
   - Configure your OpenAI API key in Settings
   - Start/Cancel analysis
   - Monitor progress and view logs

### Command-Line Mode

Run the analyzer in CLI mode:
```cmd
run_raiversing.bat --cli <path_to_idb> <openai_api_key>
```

Example:
```cmd
run_raiversing.bat --cli "C:\reverse_engineering\target.idb" "sk-your-api-key"
```

### Linux/macOS
Run the analyzer directly with Python:
```bash
# GUI Mode
python raiversing_gui.py

# CLI Mode
python raiversing_core.py <path_to_idb> <openai_api_key>
```

The program will:
1. Load the IDB file in headless mode
2. Analyze all functions using OpenAI's GPT-4
3. Improve function names and add documentation
4. Save changes back to the IDB file

## Environment Setup

### Windows
The environment is automatically set up by `setup_env.bat`, which configures:
- IDA_DIR: Path to IDA Pro installation
- PYTHONPATH: Includes IDA's Python directory
- PATH: Includes IDA's directory for DLL loading

### Linux/macOS
Set these environment variables manually:
```bash
export IDA_DIR=/opt/ida-pro
export PYTHONPATH=$IDA_DIR/python:$PYTHONPATH
```

## Configuration

### Settings
The GUI provides a Settings dialog to manage:
- OpenAI API key
- (Future: Model selection, batch size, etc.)

Settings are stored in:
- Windows: `%USERPROFILE%\.raiversing\config.ini`
- Linux/macOS: `~/.raiversing/config.ini`

## Notes

- The program requires access to IDA Pro's libraries and Python bindings
- Changes are saved automatically every 100 functions
- Analysis can be interrupted with the Cancel button or Ctrl+C in CLI mode
- Large functions are automatically truncated to manage API token limits
- On Windows, make sure to run the program with the provided batch files to ensure proper environment setup

## Troubleshooting

### Windows Common Issues
1. "DLL not found" errors:
   - Make sure `setup_env.bat` points to the correct IDA Pro directory
   - Try running as administrator if DLL loading fails

2. Python import errors:
   - Verify Python 3.12 is installed and in the correct path
   - Check if PYTHONPATH is set correctly in `setup_env.bat`

3. IDA Pro errors:
   - Ensure IDA Pro is properly installed
   - Check if all required IDA Python files are present in the IDA Pro python directory

4. GUI issues:
   - Make sure tkinter is installed (comes with Python by default)
   - Try running in CLI mode if GUI fails

## License

This project is licensed under the MIT License - see the LICENSE file for details. 