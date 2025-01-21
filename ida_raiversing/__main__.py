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
import ida_raiversing.engine as engine
import ida_raiversing.openai_module as openai_module

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
        
        self.save_btn = QPushButton("Save State")
        self.save_btn.clicked.connect(self.save_state)
        self.save_btn.setEnabled(False)
        button_layout.addWidget(self.save_btn)
        
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
            ai_module = openai_module.OpenAIModule(
                api_key_path=self.api_key_path,
                model=self.model_combo.currentText()
            )
            
            # Initialize engine
            self.engine = engine.ReversingEngine(
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
            self.save_btn.setEnabled(False)
            self.append_log("Analysis started...")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            
    def analysis_finished(self):
        self.start_btn.setEnabled(True)
        self.save_btn.setEnabled(True)
        self.append_log("Analysis completed successfully!")
        
    def analysis_error(self, error_msg):
        self.start_btn.setEnabled(True)
        self.save_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", error_msg)
        
    def save_state(self):
        if not self.engine:
            return
            
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Save State File",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        if file_name:
            try:
                self.engine.save_state(file_name)
                self.append_log(f"State saved to {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save state: {str(e)}")

def main():
    # Use IDA's built-in Qt application instance
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    
    # Don't call sys.exit() in IDA Pro
    if not hasattr(app, '_in_ida'):
        sys.exit(app.exec_()) 