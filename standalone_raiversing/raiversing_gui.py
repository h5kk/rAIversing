"""
GUI interface for standalone rAIversing application
"""

import os
import sys
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional
import configparser
from raiversing_core import IDBAnalyzer

class SettingsDialog(tk.Toplevel):
    """Dialog for managing settings like API key."""
    def __init__(self, parent, config_file: str):
        super().__init__(parent)
        self.parent = parent
        self.config_file = config_file
        self.api_key = tk.StringVar()
        
        # Load existing settings
        self.config = configparser.ConfigParser()
        if os.path.exists(config_file):
            self.config.read(config_file)
            if 'Settings' in self.config:
                self.api_key.set(self.config.get('Settings', 'api_key', fallback=''))
        
        self.title("rAIversing Settings")
        self.setup_ui()
        
        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        
    def setup_ui(self):
        """Set up the settings dialog UI."""
        # Create main frame with padding
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # API Key section
        ttk.Label(main_frame, text="OpenAI API Key:").grid(row=0, column=0, sticky=tk.W, pady=5)
        api_key_entry = ttk.Entry(main_frame, textvariable=self.api_key, width=50, show="*")
        api_key_entry.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Show/Hide API key
        self.show_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(main_frame, text="Show API Key", 
                       variable=self.show_key, 
                       command=lambda: api_key_entry.configure(show="" if self.show_key.get() else "*")
        ).grid(row=2, column=0, sticky=tk.W, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Save", command=self.save_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side=tk.LEFT, padx=5)
        
    def save_settings(self):
        """Save settings to config file."""
        if not self.config.has_section('Settings'):
            self.config.add_section('Settings')
            
        self.config['Settings']['api_key'] = self.api_key.get()
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        
        with open(self.config_file, 'w') as f:
            self.config.write(f)
            
        self.destroy()

class MainWindow:
    """Main application window."""
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("rAIversing")
        self.root.geometry("600x400")
        
        # Configuration
        self.config_dir = os.path.join(os.path.expanduser("~"), ".raiversing")
        self.config_file = os.path.join(self.config_dir, "config.ini")
        
        # Load settings
        self.config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the main window UI."""
        # Create main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # IDB File selection
        ttk.Label(main_frame, text="IDB File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.idb_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.idb_path, width=50).grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=5
        )
        
        ttk.Button(main_frame, text="Browse", command=self.browse_idb).grid(
            row=0, column=2, sticky=tk.W, padx=5
        )
        
        # Progress section
        ttk.Label(main_frame, text="Progress:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(
            main_frame, 
            variable=self.progress_var,
            maximum=100,
            length=400
        )
        self.progress.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Status text
        self.status_text = tk.Text(main_frame, height=15, width=60, wrap=tk.WORD)
        self.status_text.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Scrollbar for status text
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.status_text.yview)
        scrollbar.grid(row=2, column=3, sticky=(tk.N, tk.S))
        self.status_text['yscrollcommand'] = scrollbar.set
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        ttk.Button(button_frame, text="Settings", command=self.show_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Start Analysis", command=self.start_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel_analysis).pack(side=tk.LEFT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(main_frame, textvariable=self.status_var).grid(
            row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5
        )
        
    def browse_idb(self):
        """Open file dialog to select IDB file."""
        filename = filedialog.askopenfilename(
            title="Select IDB file",
            filetypes=[("IDA Database", "*.idb *.i64"), ("All files", "*.*")]
        )
        if filename:
            self.idb_path.set(filename)
            
    def show_settings(self):
        """Show settings dialog."""
        SettingsDialog(self.root, self.config_file)
        
    def get_api_key(self) -> Optional[str]:
        """Get API key from settings."""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
            return self.config.get('Settings', 'api_key', fallback=None)
        return None
        
    def log_message(self, message: str):
        """Add message to status text."""
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.see(tk.END)
        self.root.update()
        
    def start_analysis(self):
        """Start the analysis process."""
        idb_path = self.idb_path.get()
        if not idb_path:
            messagebox.showerror("Error", "Please select an IDB file.")
            return
            
        api_key = self.get_api_key()
        if not api_key:
            messagebox.showerror("Error", "Please set your OpenAI API key in Settings.")
            return
            
        if not os.path.exists(idb_path):
            messagebox.showerror("Error", "Selected IDB file does not exist.")
            return
            
        # Create analyzer instance
        analyzer = IDBAnalyzer(idb_path, api_key)
        
        # Override print function to log to GUI
        def gui_print(*args, **kwargs):
            message = " ".join(map(str, args))
            self.log_message(message)
            
        # Store original print function
        original_print = print
        print = gui_print
        
        try:
            # Start analysis
            self.status_var.set("Analyzing...")
            self.progress_var.set(0)
            
            # Run analysis
            success = analyzer.run()
            
            if success:
                self.status_var.set("Analysis completed successfully!")
                messagebox.showinfo("Success", "Analysis completed successfully!")
            else:
                self.status_var.set("Analysis failed.")
                messagebox.showerror("Error", "Analysis failed. Check the log for details.")
                
        except Exception as e:
            self.status_var.set("Error during analysis")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            
        finally:
            # Restore original print function
            print = original_print
            
    def cancel_analysis(self):
        """Cancel the analysis process."""
        # TODO: Implement cancellation logic
        self.status_var.set("Cancelling...")
        
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()

def main():
    """Main entry point."""
    app = MainWindow()
    app.run()

if __name__ == "__main__":
    main() 