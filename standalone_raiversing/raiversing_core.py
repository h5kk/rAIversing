"""
Standalone rAIversing application for analyzing IDA Pro databases
This module provides core functionality for analyzing IDB files without the IDA GUI
"""

import os
import sys
import json
import threading
import queue
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Any
import tiktoken
from openai import OpenAI

# IDA Python imports
import ida_idaapi
import ida_loader
import ida_auto
import ida_kernwin
import ida_pro
import ida_funcs
import ida_hexrays
import ida_name
import ida_lines
import ida_typeinf
import idautils
import idc

# Global configuration
MAX_THREADS = 4
INITIAL_BATCH_SIZE = 10
MIN_BATCH_SIZE = 1
SAVE_INTERVAL = 100
MODEL_NAME = "gpt-4-0125-preview"
MAX_TOKENS = 16000
MAX_CODE_LINES = 1000
MAX_SUBFUNCTION_LINES = 300
ENCODING = tiktoken.encoding_for_model("gpt-4")

class AnalysisProgress:
    """Track progress of function analysis."""
    def __init__(self):
        self.total_funcs = 0
        self.processed_funcs = 0
        self.current_func = None
        
    def update(self, func_name=None):
        self.processed_funcs += 1
        self.current_func = func_name
        
    def get_progress(self):
        if self.total_funcs == 0:
            return 0
        return (self.processed_funcs * 100) / self.total_funcs

class IDBAnalyzer:
    """Main class for analyzing IDB files."""
    def __init__(self, idb_path: str, api_key: str):
        self.idb_path = idb_path
        self.api_key = api_key
        self.client = OpenAI(api_key=api_key)
        self.progress = AnalysisProgress()
        self.analysis_cancelled = False
        self.analysis_lock = threading.Lock()
        self.ui_queue = queue.Queue()
        
    def initialize_ida(self) -> bool:
        """Initialize IDA in headless mode."""
        try:
            # Enable batch mode
            ida_kernwin.cvar.batch = 1
            
            # Load the IDB file
            if ida_loader.load_file(self.idb_path, 0) != 0:
                print(f"Failed to load IDB: {self.idb_path}")
                return False
                
            # Wait for analysis to complete
            ida_auto.auto_wait()
            return True
            
        except Exception as e:
            print(f"Error initializing IDA: {str(e)}")
            return False
            
    def get_function_info(self, func_addr: int) -> Optional[Dict]:
        """Get information about a function."""
        print(f"\nAnalyzing function at {hex(func_addr)}")
        func = ida_funcs.get_func(func_addr)
        if not func:
            print(f"No function found at {hex(func_addr)}")
            return None
            
        try:
            # Get decompiled code
            cfunc = ida_hexrays.decompile(func)
            if not cfunc:
                print(f"Could not decompile function at {hex(func_addr)}")
                return None
                
            # Get the pseudocode as text
            code = str(cfunc)
            
            # Limit code size for very large functions
            code_lines = code.split('\n')
            if len(code_lines) > MAX_CODE_LINES:
                print(f"[WARNING] Function is very large ({len(code_lines)} lines). Truncating to {MAX_CODE_LINES} lines.")
                signature_end = 0
                for i, line in enumerate(code_lines):
                    if '{' in line:
                        signature_end = i + 1
                        break
                
                portion_size = (MAX_CODE_LINES - signature_end - 1) // 2
                first_portion = code_lines[:signature_end + portion_size]
                last_portion = code_lines[-portion_size:]
                
                code_lines = first_portion + ['// ... (truncated) ...'] + last_portion
                code = '\n'.join(code_lines)
            
            # Get sub-functions called by this function
            subfuncs = []
            seen_funcs = set()
            
            for xref in idautils.XrefsFrom(func_addr, ida_idaapi.XREF_FAR):
                if xref.type in [ida_idaapi.fl_CN, ida_idaapi.fl_CF]:
                    sub_addr = xref.to
                    if sub_addr not in seen_funcs and sub_addr != func_addr:
                        called_func = ida_funcs.get_func(sub_addr)
                        if called_func:
                            seen_funcs.add(sub_addr)
                            
                            # Get subfunction code with size limit
                            sub_cfunc = ida_hexrays.decompile(called_func)
                            if sub_cfunc:
                                sub_code = str(sub_cfunc)
                                sub_lines = sub_code.split('\n')
                                if len(sub_lines) > MAX_SUBFUNCTION_LINES:
                                    sub_code = '\n'.join(sub_lines[:MAX_SUBFUNCTION_LINES] + ['// ... (truncated) ...'])
                            else:
                                sub_code = "// Could not decompile subfunction"
                            
                            subfuncs.append({
                                "address": sub_addr,
                                "name": ida_funcs.get_func_name(sub_addr),
                                "type": "sub_function",
                                "code": sub_code
                            })
            
            # Get variable info
            variables = []
            for lvar in cfunc.lvars:
                var_info = {
                    "name": str(lvar.name),
                    "type": str(lvar.type()),
                    "is_arg": lvar.is_arg_var,
                    "location": str(lvar.location),
                    "defea": lvar.defea,
                    "size": lvar.width,
                    "is_result": lvar.is_result_var,
                    "comments": []
                }
                variables.append(var_info)
                    
            return {
                "address": func_addr,
                "name": ida_funcs.get_func_name(func_addr),
                "code": code,
                "variables": variables,
                "subfunctions": subfuncs,
                "calls": list(seen_funcs),
                "called_by": [x.frm for x in idautils.XrefsTo(func_addr, 1) if ida_funcs.get_func(x.frm) and x.frm != func_addr],
                "comments": ida_lines.get_extra_cmt(func_addr, 0) or ""
            }
        except Exception as e:
            print(f"Error getting function info for {hex(func_addr)}: {str(e)}")
            return None

    def analyze_function_with_ai(self, func_info: Dict) -> Optional[Dict]:
        """Analyze function using OpenAI API."""
        if not func_info:
            return None
            
        try:
            # Clean up the code for better formatting
            code = func_info['code'].replace('\t', '    ')
            
            # Build the variables section
            variables_text = []
            for v in func_info['variables']:
                var_str = f"  * {v['name']}: {v['type']}"
                if v.get('is_arg'):
                    var_str += " (argument)"
                if v.get('is_result'):
                    var_str += " (return value)"
                variables_text.append(var_str)
            
            # Build the subfunctions section
            subfuncs_text = []
            for sub in func_info.get('subfunctions', []):
                sub_text = f"\nSubfunction {sub['name']} at {hex(sub['address'])}:\n{sub.get('code', '')}"
                subfuncs_text.append(sub_text)
            
            # Create the prompt
            prompt = (
                "Analyze this decompiled C++ function and its subfunctions. "
                "Provide suggestions for better names and documentation.\n\n"
                f"Function Information:\n"
                f"- Name: {func_info['name']}\n"
                f"- Variables:\n"
                f"{chr(10).join(variables_text)}\n\n"
                f"Decompiled code:\n"
                f"{code}\n\n"
                f"Called by: {[hex(x) for x in func_info['called_by']]}\n"
                f"Calls to: {[hex(x) for x in func_info['calls']]}\n\n"
                f"Sub-functions:\n"
                f"{chr(10).join(subfuncs_text)}\n\n"
            )

            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a reverse engineering assistant specialized in analyzing C++ code. Pay special attention to security implications, buffer usage, and error handling."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=MAX_TOKENS
            )
            
            return json.loads(response.choices[0].message.content)
            
        except Exception as e:
            print(f"Error calling OpenAI API: {str(e)}")
            return None

    def improve_function(self, func_addr: int, visited: Optional[Set[int]] = None) -> bool:
        """Improve a single function's name, variables, and comments."""
        if visited is None:
            visited = set()
            
        if func_addr in visited:
            return False
            
        visited.add(func_addr)
        
        func_info = self.get_function_info(func_addr)
        if not func_info:
            return False
            
        # Skip compiler functions
        if func_info['name'].startswith('__'):
            return False
            
        print(f"\nAnalyzing function: {func_info['name']}")
        
        suggestions = self.analyze_function_with_ai(func_info)
        if not suggestions:
            return False
            
        improved = False
        
        try:
            # Update function name
            new_name = suggestions.get("function_name")
            if new_name and new_name != func_info['name']:
                if not new_name.endswith(f"_{hex(func_addr)[2:]}"):
                    new_name = f"{new_name}_{hex(func_addr)[2:]}"
                if ida_name.force_name(func_addr, new_name):
                    print(f"Renamed function to: {new_name}")
                    improved = True
                    
            # Add function description and analysis as comments
            if suggestions.get("description") or suggestions.get("analysis"):
                comment = ""
                if suggestions.get("description"):
                    comment = suggestions["description"] + "\n\n"
                if suggestions.get("analysis"):
                    comment += suggestions["analysis"]
                if comment:
                    if idc.set_func_cmt(func_addr, comment, 0):
                        improved = True
                        
            # Process all subfunctions
            for called_func in func_info["subfunctions"]:
                if called_func["address"] not in visited:
                    if self.improve_function(called_func["address"], visited):
                        improved = True
                        
        except Exception as e:
            print(f"Error improving function: {str(e)}")
            
        return improved

    def process_all_functions(self):
        """Process all functions in the IDB file."""
        try:
            # Get all functions
            all_functions = list(idautils.Functions())
            self.progress.total_funcs = len(all_functions)
            
            print(f"\nFound {len(all_functions)} functions to analyze")
            
            # Process in batches using ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                futures = []
                for func_addr in all_functions:
                    if self.analysis_cancelled:
                        break
                    futures.append(executor.submit(self.improve_function, func_addr))
                    
                # Process results as they complete
                improved_count = 0
                for future in as_completed(futures):
                    if future.result():
                        improved_count += 1
                        
                    # Auto-save periodically
                    if improved_count % SAVE_INTERVAL == 0:
                        print(f"\nAuto-saving database after {improved_count} improvements...")
                        ida_loader.save_database(self.idb_path, 0)
                        
            # Final save
            print("\nSaving final changes to database...")
            ida_loader.save_database(self.idb_path, 0)
            
            print(f"\nCompleted! Improved {improved_count} functions")
            
        except Exception as e:
            print(f"Error processing functions: {str(e)}")
            print(traceback.format_exc())
            
    def run(self):
        """Main entry point for analysis."""
        if not self.initialize_ida():
            return False
            
        try:
            self.process_all_functions()
            return True
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            return False
        finally:
            # Clean exit
            ida_pro.qexit(0)

def main():
    """Main entry point."""
    if len(sys.argv) != 3:
        print("Usage: python raiversing_core.py <path_to_idb> <openai_api_key>")
        return
        
    idb_path = sys.argv[1]
    api_key = sys.argv[2]
    
    if not os.path.exists(idb_path):
        print(f"IDB file not found: {idb_path}")
        return
        
    analyzer = IDBAnalyzer(idb_path, api_key)
    analyzer.run()

if __name__ == "__main__":
    main()
