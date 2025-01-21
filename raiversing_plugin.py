"""
IDA Pro plugin for AI-powered reverse engineering
"""

import sys
import os
import logging
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, 
    QPushButton, QTextEdit, QLabel, QSpinBox,
    QComboBox, QFileDialog, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# IDA Pro imports
import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_hexrays
import ida_name
import idautils
import idc

import json
from dotenv import load_dotenv
import openai

# Plugin metadata
PLUGIN_NAME = "rAIversing"
PLUGIN_HOTKEY = "Ctrl-Alt-R"

class LogHandler(logging.Handler):
    def __init__(self, signal):
        super().__init__()
        self.signal = signal
        
    def emit(self, record):
        msg = self.format(record)
        self.signal.emit(msg)

class AnalysisThread(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    
    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        
    def run(self):
        try:
            self.engine.improve_all_functions()
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

class ReversingEngine:
    def __init__(self, ai_module, batch_size: int = 5):
        self.ai_module = ai_module
        self.batch_size = batch_size
        self.logger = logging.getLogger("ReversingEngine")
        self.processed_functions = set()
        
    def get_all_functions(self):
        """Get all function addresses in the binary."""
        return list(idautils.Functions())
        
    def get_function_info(self, func_addr):
        """Get detailed information about a function."""
        func = ida_funcs.get_func(func_addr)
        if not func:
            return None
            
        try:
            # Get decompiled code
            cfunc = ida_hexrays.decompile(func)
            if not cfunc:
                return None
                
            return {
                "address": func_addr,
                "name": ida_funcs.get_func_name(func_addr),
                "code": str(cfunc),
                "calls": [x.to for x in idautils.XrefsFrom(func_addr, ida_xref.XREF_FAR) if ida_funcs.get_func(x.to)],
                "called_by": [x.frm for x in idautils.XrefsTo(func_addr, ida_xref.XREF_FAR) if ida_funcs.get_func(x.frm)]
            }
        except Exception as e:
            self.logger.error(f"Error getting function info: {str(e)}")
            return None
        
    def improve_function(self, func_addr):
        """Improve a single function using AI."""
        if func_addr in self.processed_functions:
            return True
            
        try:
            func_info = self.get_function_info(func_addr)
            if not func_info:
                return False
                
            # Get AI suggestions
            suggestion = self.ai_module.analyze_function(func_info)
            if not suggestion or "new_name" not in suggestion:
                return False
                
            # Sanitize and apply new name
            new_name = suggestion["new_name"]
            new_name = ida_name.validate_name(new_name, ida_name.VNT_VISIBLE)
            if new_name and ida_name.set_name(func_addr, new_name, ida_name.SN_CHECK):
                self.logger.info(f"Renamed {func_info['name']} to {new_name}")
                
            self.processed_functions.add(func_addr)
            return True
            
        except Exception as e:
            self.logger.error(f"Error improving function at {hex(func_addr)}: {str(e)}")
            return False
            
    def improve_all_functions(self):
        """Improve all functions in the binary."""
        functions = self.get_all_functions()
        total = len(functions)
        self.logger.info(f"Found {total} functions to analyze")
        
        for i, func_addr in enumerate(functions, 1):
            self.logger.info(f"Processing function {i}/{total}: {hex(func_addr)}")
            self.improve_function(func_addr)

class AIModule:
    def __init__(self, api_key_path=None, model="gpt-4-1106-preview"):
        self.model = model
        
        # Try to load API key
        load_dotenv()
        if api_key_path and Path(api_key_path).exists():
            openai.api_key = Path(api_key_path).read_text().strip()
        elif os.getenv("OPENAI_API_KEY"):
            openai.api_key = os.getenv("OPENAI_API_KEY")
        else:
            raise ValueError("No OpenAI API key found")
            
    def analyze_function(self, func_info):
        """Analyze a function using OpenAI."""
        try:
            prompt = f"""Analyze this decompiled function and suggest a better name:

Code:
{func_info['code']}

Context:
- Called by: {', '.join(hex(x) for x in func_info['called_by'])}
- Calls: {', '.join(hex(x) for x in func_info['calls'])}

Respond with a JSON object containing:
{{"new_name": "suggested_function_name"}}

Rules for the new name:
1. Must be a valid C identifier (letters, numbers, underscores)
2. Must start with a letter or underscore
3. Should be descriptive but not too long
4. Should follow common naming conventions
5. Should not include special characters"""

            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert reverse engineer."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7
            )
            
            return json.loads(response.choices[0].message.content)
            
        except Exception as e:
            print(f"Error calling OpenAI API: {str(e)}")
            return None

class MainWindow(QMainWindow):
    log_signal = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("rAIversing")
        self.setMinimumSize(800, 600)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create settings section
        settings_layout = QHBoxLayout()
        
        # Model selection
        model_label = QLabel("Model:")
        self.model_combo = QComboBox()
        self.model_combo.addItems([
            "gpt-4-1106-preview",
            "gpt-3.5-turbo-16k",
            "gpt-4",
            "gpt-4-32k"
        ])
        settings_layout.addWidget(model_label)
        settings_layout.addWidget(self.model_combo)
        
        # Batch size
        batch_label = QLabel("Batch Size:")
        self.batch_spin = QSpinBox()
        self.batch_spin.setRange(1, 10)
        self.batch_spin.setValue(5)
        settings_layout.addWidget(batch_label)
        settings_layout.addWidget(self.batch_spin)
        
        # API Key selection
        self.api_key_btn = QPushButton("Select API Key File")
        self.api_key_btn.clicked.connect(self.select_api_key)
        settings_layout.addWidget(self.api_key_btn)
        
        # Add settings to main layout
        layout.addLayout(settings_layout)
        
        # Create log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)
        
        # Create buttons
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Analysis")
        self.start_btn.clicked.connect(self.start_analysis)
        button_layout.addWidget(self.start_btn)
        
        layout.addLayout(button_layout)
        
        # Setup logging
        self.setup_logging()
        
        # Initialize variables
        self.api_key_path = None
        self.engine = None
        self.analysis_thread = None
        
    def setup_logging(self):
        self.log_signal.connect(self.append_log)
        handler = LogHandler(self.log_signal)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        logger = logging.getLogger()
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        
    def append_log(self, message):
        self.log_output.append(message)
        self.log_output.verticalScrollBar().setValue(
            self.log_output.verticalScrollBar().maximum()
        )
        
    def select_api_key(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Select API Key File",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        if file_name:
            self.api_key_path = file_name
            self.api_key_btn.setText("API Key Selected ✓")
            
    def start_analysis(self):
        if not self.api_key_path and not os.getenv("OPENAI_API_KEY"):
            QMessageBox.warning(
                self,
                "Error",
                "Please select an API key file or set OPENAI_API_KEY environment variable"
            )
            return
            
        try:
            # Initialize AI module
            ai_module = AIModule(
                api_key_path=self.api_key_path,
                model=self.model_combo.currentText()
            )
            
            # Initialize engine
            self.engine = ReversingEngine(
                ai_module,
                batch_size=self.batch_spin.value()
            )
            
            # Start analysis in thread
            self.analysis_thread = AnalysisThread(self.engine)
            self.analysis_thread.progress.connect(self.append_log)
            self.analysis_thread.finished.connect(self.analysis_finished)
            self.analysis_thread.error.connect(self.analysis_error)
            
            self.analysis_thread.start()
            
            # Update UI
            self.start_btn.setEnabled(False)
            self.append_log("Analysis started...")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            
    def analysis_finished(self):
        self.start_btn.setEnabled(True)
        self.append_log("Analysis completed successfully!")
        
    def analysis_error(self, error_msg):
        self.start_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", error_msg)

class RAIversingPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "AI-powered reverse engineering assistant"
    help = "Uses GPT-4 to analyze and improve function names"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    
    def init(self):
        return ida_idaapi.PLUGIN_OK
        
    def run(self, arg):
        try:
            app = QApplication.instance()
            if not app:
                app = QApplication(sys.argv)
            window = MainWindow()
            window.show()
        except Exception as e:
            ida_kernwin.warning(f"Error loading rAIversing: {str(e)}")
        
    def term(self):
        pass

def PLUGIN_ENTRY():
    return RAIversingPlugin() 