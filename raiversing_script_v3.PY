"""
IDA Pro script for AI-powered reverse engineering
Run from IDA's Script Command (Alt+F7)
"""

import os
import json
import threading
import ida_funcs
import ida_hexrays
import ida_name
import ida_kernwin
import ida_idaapi
import idautils
import idc
import ida_lines
import ida_typeinf
from openai import OpenAI
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import tiktoken
import re
import traceback
import ida_loader  # Add to imports at top

# Initialize OpenAI client
client = OpenAI(api_key="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")  # Replace with your actual API key securely

# Global state for cancellation and thread safety
g_analysis_cancelled = False
g_analysis_lock = threading.Lock()
g_ui_queue = queue.Queue()

# Configuration
MAX_THREADS = 4  # Adjust based on your API rate limits and system capabilities
INITIAL_BATCH_SIZE = 10  # Initial number of functions to analyze in a single API call
MIN_BATCH_SIZE = 1  # Minimum batch size when auto-adjusting
SAVE_INTERVAL = 100  # Save database every N functions
MODEL_NAME = "gpt-4o-mini-2024-07-18"  # GPT-4 with 128k context
MAX_TOKENS = 16000  # Maximum tokens for output
MAX_CODE_LINES = 1000  # Maximum lines of code to analyze at once
MAX_SUBFUNCTION_LINES = 300  # Maximum lines of code for each subfunction
ENCODING = tiktoken.encoding_for_model("gpt-4")  # Use GPT-4 encoding

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

class AnalysisUI:
    """Handle UI updates during analysis."""
    def __init__(self):
        self.progress = AnalysisProgress()
        
    def show_wait_box(self, message):
        ida_kernwin.show_wait_box(message)
        
    def hide_wait_box(self):
        ida_kernwin.hide_wait_box()
        
    def replace_wait_box(self, message):
        ida_kernwin.replace_wait_box(message)
        
    def user_cancelled(self):
        return ida_kernwin.user_cancelled()

def count_tokens(text):
    """Count the number of tokens in a text string."""
    try:
        return len(ENCODING.encode(text))
    except Exception as e:
        print(f"Error counting tokens: {str(e)}")
        return len(text) // 4  # Rough estimate if encoding fails


def analyze_function_with_ai(func_info):
    """Analyze function using OpenAI API."""
    if not func_info:
        return None
        
    try:
        # Clean up the code for better formatting
        code = func_info['code'].replace('\t', '    ')
        
        # Count tokens in the main function code
        code_tokens = count_tokens(code)
        if code_tokens > MAX_TOKENS // 2:
            print(f"[WARNING] Function code is too large ({code_tokens} tokens). Analysis may be incomplete.")
            
        # Build the variables section with token limit
        variables_text = []
        var_tokens = 0
        for v in func_info['variables']:
            var_str = f"  * {v['name']}: {v['type']}"
            if v.get('is_arg'):
                var_str += " (argument)"
            if v.get('is_result'):
                var_str += " (return value)"
            var_tokens += count_tokens(var_str)
            if var_tokens > MAX_TOKENS // 4:
                variables_text.append("// ... (additional variables truncated) ...")
                break
            variables_text.append(var_str)
        
        # Build the subfunctions section with token limit
        subfuncs_text = []
        subfunc_tokens = 0
        for sub in func_info.get('subfunctions', []):
            sub_text = f"\nSubfunction {sub['name']} at {hex(sub['address'])}:\n{sub.get('code', '')}"
            sub_tokens = count_tokens(sub_text)
            if subfunc_tokens + sub_tokens > MAX_TOKENS // 4:
                subfuncs_text.append("\n// ... (additional subfunctions truncated) ...")
                break
            subfuncs_text.append(sub_text)
            subfunc_tokens += sub_tokens

        # Create the prompt using concatenation instead of a single f-string
        json_schema = (
            "{\n"
            '    "function_name": "suggested_function_name",\n'
            '    "description": "Brief description of what the function does",\n'
            '    "variables": [\n'
            "        {\n"
            '            "old_name": "original_variable_name",\n'
            '            "new_name": "suggested_variable_name",\n'
            '            "explanation": "why this name is better",\n'
            '            "type": "variable_type"\n'
            "        }\n"
            "    ],\n"
            '    "analysis": "Detailed analysis of the function",\n'
            '    "subfunctions": [\n'
            "        {\n"
            '            "name": "original_subfunction_name",\n'
            '            "suggested_name": "better_name",\n'
            '            "purpose": "what this subfunction does",\n'
            '            "variables": [],\n'
            '            "analysis": "Detailed analysis of the subfunction"\n'
            "        }\n"
            "    ]\n"
            "}"
        )
        
        prompt = (
            "Analyze this decompiled C++ function and its subfunctions. Provide a JSON response with no markdown formatting or code block markers.\n\n"
            f"Function Information:\n"
            f"- Name: {func_info['name']}\n"
            f"- Variables:\n"
            f"{chr(10).join(variables_text)}\n\n"
            f"Decompiled code:\n"
            f"{code}\n\n"
            f"Called by: {[hex(x) for x in func_info['called_by']]}\n"
            f"Calls to: {[hex(x) for x in func_info['calls']]}\n\n"
            f"Sub-functions called:\n"
            f"{chr(10).join(subfuncs_text)}\n\n"
            "Analyze each subfunction separately and include their suggestions in the JSON response.\n\n"
            "Provide the analysis in a JSON object with the following structure:\n"
            f"{json_schema}\n\n"
            "Naming rules:\n"
            "1. Use descriptive names that reflect purpose\n"
            "2. Start function names with verbs (e.g. calculate, process, validate)\n"
            "3. For variables:\n"
            "   - Use nouns or noun phrases\n"
            "   - Indicate type in name (e.g. count_ptr, data_size)\n"
            "   - Use standard prefixes (is_, has_, num_, etc.)\n"
            "   - Keep original name if already descriptive\n"
            "4. For parameters:\n"
            "   - param_1 -> input_value, data_ptr, etc.\n"
            "   - Reflect purpose and type\n"
            "5. For temporary variables:\n"
            "   - temp_result, calc_value, etc.\n"
            "   - Indicate what they store\n"
            "6. Special cases:\n"
            "   - Pointers: add _ptr suffix\n"
            "   - Arrays: add _array suffix\n"
            "   - Flags: use is_ or has_ prefix\n"
            "   - Counters: use count_ or num_ prefix\n"
            "7. Avoid:\n"
            "   - Single letter names (i, j, k)\n"
            "   - Generic names (temp, var)\n"
            "   - Unclear abbreviations\n"
            "   - Platform-specific prefixes\n\n"
            "Focus on:\n"
            "- Function arguments and return values\n"
            "- Buffer sizes and array lengths\n"
            "- Error handling variables\n"
            "- Control flow flags\n"
            "- Mutex and synchronization objects\n"
            "- Security implications\n"
            "- Understanding the purpose of each subfunction"
        )

        # Use IDA's script timeout disabler during API call
        with ida_kernwin.disabled_script_timeout_t():
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a reverse engineering assistant specialized in analyzing C++ code. You provide analysis in strict JSON format with no additional text, no markdown formatting, and no code block markers. Pay special attention to security implications, buffer usage, and error handling. When suggesting names:\n1. Be specific and descriptive\n2. Use standard prefixes/suffixes\n3. Indicate types where helpful\n4. Keep existing good names\n5. Follow C++ naming conventions"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=MAX_TOKENS
            )
        
        # Log raw response for debugging
        raw_response = response.choices[0].message.content
        print("AI Response:", raw_response)
        
        # Clean up the response by removing any markdown or code block markers
        cleaned_response = re.sub(r'^```\w*\n|\n```$', '', raw_response.strip())
        print("\nCleaned Response:", cleaned_response)
        
        try:
            suggestions = json.loads(cleaned_response)
            # Validate required fields
            required_fields = ["function_name", "description", "variables", "analysis", "subfunctions"]
            if not all(field in suggestions for field in required_fields):
                print("Warning: Response missing required fields")
                return None
            return suggestions
        except json.JSONDecodeError as e:
            print(f"Error parsing OpenAI response: {str(e)}")
            print("Response content:", raw_response)
            return None
            
    except Exception as e:
        print(f"Error calling OpenAI API: {str(e)}")
        return None

def is_compiler_function(func_name):
    """Check if a function is likely compiler-generated."""
    # Common compiler-generated function prefixes
    compiler_prefixes = [
        '__asm',
        '__cdecl',
        '__stdcall',
        '__fastcall',
        '__thiscall',
        '__clrcall',
        '__vectorcall',
        '_alloca',
        '_CxxThrowException',
        'std::',
        'operator new',
        'operator delete',
        'nullsub_',
        'j_nullsub_',
        'unknown_libname_',
        'SEH_',
        'EH_',
        'CRT_'
    ]
    
    # Only consider it a compiler function if it matches these exact patterns
    return any(
        (prefix == func_name or func_name.startswith(prefix + "_"))
        for prefix in compiler_prefixes
    )

class VariableRenamer(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_changes):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_changes = var_changes
        
    def modify_lvars(self, lvars):
        """Modify local variables with proper type handling."""
        modified = False
        
        # First pass: collect all variables and their types
        var_types = {}
        for lvar in lvars.lvvec:
            var_types[str(lvar.name)] = str(lvar.type())
            
        # Second pass: rename variables and set types
        for lvar in lvars.lvvec:
            old_name = str(lvar.name)
            if old_name in self.var_changes:
                new_name, explanation, var_type = self.var_changes[old_name]
                
                # Validate the new name
                uname = ida_name.validate_name(str(new_name), ida_name.VNT_VISIBLE)
                if uname:
                    # Set the name
                    lvar.name = uname
                    print(f"Renamed variable {old_name} to {new_name}")
                    
                    # Set the comment with type information
                    comment = f"{var_type}: {explanation}"
                    if "undefined" in var_types.get(old_name, "").lower():
                        comment = f"[WARNING: Possibly undefined] {comment}"
                    lvar.cmt = comment
                    
                    # Try to parse and set the type if provided
                    if var_type:
                        try:
                            tif = ida_typeinf.tinfo_t()
                            if ida_typeinf.parse_decl(tif, None, var_type, 0):
                                lvar.set_final_type(tif)
                                print(f"Set type for {new_name} to {var_type}")
                        except:
                            print(f"Could not set type {var_type} for {new_name}")
                    
                    modified = True
                    
        return modified

def improve_function(func_addr, ui=None, visited=None, depth=0):
    """Improve a single function's name, variables, and comments."""
    global g_analysis_cancelled
    
    if g_analysis_cancelled:
        return False
        
    indent = "  " * depth
    log_debug(f"{indent}Starting analysis of function at {hex(func_addr)}")
    
    if visited is None:
        visited = set()

    if func_addr in visited:
        log_debug(f"{indent}Already visited function at {hex(func_addr)}")
        return False

    visited.add(func_addr)
    log_debug(f"{indent}Added {hex(func_addr)} to visited set")

    func_info = get_function_info(func_addr)
    if not func_info:
        log_debug(f"{indent}Could not get info for function at {hex(func_addr)}")
        return False

    # Only skip very specific compiler functions
    if func_info['name'].startswith('__') and any(x in func_info['name'] for x in ['ctor', 'dtor', 'vector', 'exception']):
        log_debug(f"{indent}Skipping compiler function: {func_info['name']}")
        return False

    if ui:
        ui.replace_wait_box(f"Analyzing function: {func_info['name']}")
        if ui.user_cancelled():
            g_analysis_cancelled = True
            return False

    print(f"\n{indent}Analyzing function at {hex(func_addr)}: {func_info['name']}")

    # First analyze all subfunctions to get their info for context
    subfunction_results = {}
    if func_info["subfunctions"]:
        log_debug(f"{indent}Pre-analyzing {len(func_info['subfunctions'])} subfunctions")
        for called_func in func_info["subfunctions"]:
            if called_func["address"] not in visited:
                log_debug(f"{indent}Pre-analyzing: {called_func['name']} at {hex(called_func['address'])}")
                sub_info = get_function_info(called_func["address"])
                if sub_info:
                    subfunction_results[called_func["address"]] = sub_info

    # Now get suggestions with full context
    log_debug(f"{indent}Getting AI suggestions for {hex(func_addr)}")
    suggestions = analyze_function_with_ai(func_info)
    if not suggestions:
        log_debug(f"{indent}No suggestions received for {hex(func_addr)}")
        return False

    improved = False

    try:
        # Execute UI operations in the main thread
        def update_ui():
            nonlocal improved
            
            # Update function name
            new_name = suggestions.get("function_name")
            if new_name and new_name != func_info['name']:
                # Add address suffix if not present
                if not new_name.endswith(f"_{hex(func_addr)[2:]}"):
                    new_name = f"{new_name}_{hex(func_addr)[2:]}"
                    
                log_debug(f"{indent}Attempting to rename function to: {new_name}")
                if ida_name.force_name(func_addr, new_name):
                    print(f"{indent}Renamed function to: {new_name}")
                    improved = True
                else:
                    log_debug(f"{indent}Failed to set function name to: {new_name}")

            # Add function description and analysis as comments
            if suggestions.get("description") or suggestions.get("analysis"):
                description = suggestions.get("description", "")
                analysis = suggestions.get("analysis", "")
                
                # Add description as a repeatable comment at the top
                if description:
                    # Clear any existing comments first
                    for i in range(1000):  # Arbitrary large number
                        if not ida_lines.del_extra_cmt(func_addr, ida_lines.E_PREV + i):
                            break
                            
                    # Add new description
                    ida_lines.add_extra_cmt(func_addr, True, "")  # Add blank line
                    ida_lines.add_extra_cmt(func_addr, True, "Description:")
                    ida_lines.add_extra_cmt(func_addr, True, "-" * 40)
                    for line in description.split('\n'):
                        ida_lines.add_extra_cmt(func_addr, True, line.strip())
                    ida_lines.add_extra_cmt(func_addr, True, "-" * 40)
                    improved = True
                    
                # Add detailed analysis as additional comments
                if analysis:
                    ida_lines.add_extra_cmt(func_addr, True, "")  # Add blank line
                    ida_lines.add_extra_cmt(func_addr, True, "Analysis:")
                    ida_lines.add_extra_cmt(func_addr, True, "-" * 40)
                    # Split analysis into lines and add each as a comment
                    analysis_lines = analysis.split('\n')
                    for line in analysis_lines:
                        if line.strip():  # Skip empty lines
                            ida_lines.add_extra_cmt(func_addr, True, line.strip())
                    ida_lines.add_extra_cmt(func_addr, True, "-" * 40)
                    improved = True
                    
        # Execute UI updates in main thread
        ida_kernwin.execute_sync(update_ui, ida_kernwin.MFF_WRITE)  # Use MFF_WRITE like Gepetto

        # Process all subfunctions
        if func_info["subfunctions"]:
            print(f"\n{indent}Analyzing called functions:")
            for called_func in func_info["subfunctions"]:
                if called_func["address"] in visited:
                    log_debug(f"{indent}Skipping already visited function: {called_func['name']}")
                    continue

                print(f"\n{indent}Analyzing called function: {called_func['name']} at {hex(called_func['address'])}")
                
                # Get suggested name from AI's subfunctions
                suggested_name = None
                subfunction_analysis = None
                for subfunc in suggestions.get("subfunctions", []):
                    if subfunc.get("name") == called_func["name"]:
                        suggested_name = subfunc.get("suggested_name")
                        subfunction_analysis = subfunc
                        log_debug(f"{indent}Found suggestion for {called_func['name']}: {suggested_name}")
                        break

                if suggested_name:
                    def update_subfunction():
                        nonlocal improved
                        
                        # Add address suffix if not present
                        if not suggested_name.endswith(f"_{hex(called_func['address'])[2:]}"):
                            suggested_name_with_addr = f"{suggested_name}_{hex(called_func['address'])[2:]}"
                        else:
                            suggested_name_with_addr = suggested_name
                            
                        if ida_name.force_name(called_func['address'], suggested_name_with_addr):
                            print(f"{indent}Renamed subfunction to: {suggested_name_with_addr}")
                            improved = True
                        else:
                            log_debug(f"{indent}Failed to set subfunction name to: {suggested_name_with_addr}")

                        # Add subfunction analysis as comments if available
                        if subfunction_analysis:
                            # Clear existing comments
                            for i in range(1000):  # Arbitrary large number
                                if not ida_lines.del_extra_cmt(called_func['address'], ida_lines.E_PREV + i):
                                    break
                                    
                            # Add purpose and analysis
                            if subfunction_analysis.get("purpose"):
                                ida_lines.add_extra_cmt(called_func['address'], True, "")
                                ida_lines.add_extra_cmt(called_func['address'], True, "Purpose:")
                                ida_lines.add_extra_cmt(called_func['address'], True, "-" * 40)
                                ida_lines.add_extra_cmt(called_func['address'], True, subfunction_analysis.get("purpose"))
                                ida_lines.add_extra_cmt(called_func['address'], True, "-" * 40)
                                
                            if subfunction_analysis.get("analysis"):
                                ida_lines.add_extra_cmt(called_func['address'], True, "")
                                ida_lines.add_extra_cmt(called_func['address'], True, "Analysis:")
                                ida_lines.add_extra_cmt(called_func['address'], True, "-" * 40)
                                for line in subfunction_analysis.get("analysis").split('\n'):
                                    if line.strip():
                                        ida_lines.add_extra_cmt(called_func['address'], True, line.strip())
                                ida_lines.add_extra_cmt(called_func['address'], True, "-" * 40)
                            
                    # Execute subfunction updates in main thread
                    ida_kernwin.execute_sync(update_subfunction, ida_kernwin.MFF_FAST)

                # Recursively improve subfunction
                log_debug(f"{indent}Recursively analyzing {called_func['name']}")
                if improve_function(called_func["address"], ui, visited, depth + 1):
                    improved = True

    except Exception as e:
        log_debug(f"{indent}Error improving function: {str(e)}")
        return improved

    if ui:
        ui.progress.update(func_info['name'])

    log_debug(f"{indent}Completed analysis of {hex(func_addr)}")
    return improved


def log_debug(msg):
    """Print a debug message with timestamp."""
    print(f"[DEBUG] {msg}")

def get_function_info(func_addr):
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
            
        # Get the pseudocode as text and debug its contents
        code = str(cfunc)
        
        # Limit code size for very large functions
        code_lines = code.split('\n')
        if len(code_lines) > MAX_CODE_LINES:
            print(f"[WARNING] Function is very large ({len(code_lines)} lines). Truncating to {MAX_CODE_LINES} lines.")
            # Keep the function signature and first part
            signature_end = 0
            for i, line in enumerate(code_lines):
                if '{' in line:
                    signature_end = i + 1
                    break
            
            # Take first and last portions of the function
            portion_size = (MAX_CODE_LINES - signature_end - 1) // 2
            first_portion = code_lines[:signature_end + portion_size]
            last_portion = code_lines[-portion_size:]
            
            code_lines = first_portion + ['// ... (truncated) ...'] + last_portion
            code = '\n'.join(code_lines)
        
        print("\n" + "="*80)
        print("DEBUG: Raw Pseudocode Content")
        print("="*80)
        print(code)
        print("="*80)
        
        # Simple sub_ detection
        print("\nDEBUG: Searching for sub_ functions")
        print("="*80)
        
        # First try direct string search
        sub_indices = []
        start = 0
        while True:
            idx = code.find("sub_", start)
            if idx == -1:
                break
            # Find the end of the function name (next non-hex character)
            end = idx + 4  # skip "sub_"
            while end < len(code) and code[end] in "0123456789ABCDEFabcdef":
                end += 1
            sub_name = code[idx:end]
            print(f"Found potential sub_ at index {idx}: {sub_name}")
            print(f"Context: ...{code[max(0, idx-20):min(len(code), idx+50)]}...")
            sub_indices.append((idx, sub_name))
            start = end
            
        print(f"\nFound {len(sub_indices)} potential sub_ functions")
        
        # Get sub-functions called by this function
        subfuncs = []
        seen_funcs = set()
        
        for _, sub_name in sub_indices:
            print(f"\nChecking {sub_name}:")
            sub_addr = ida_name.get_name_ea(ida_idaapi.BADADDR, sub_name)
            print(f"- Address lookup result: {hex(sub_addr)}")
            
            if sub_addr != ida_idaapi.BADADDR and sub_addr not in seen_funcs and sub_addr != func_addr:
                called_func = ida_funcs.get_func(sub_addr)
                if called_func:
                    print(f"- Valid function found at {hex(sub_addr)}")
                    seen_funcs.add(sub_addr)
                    
                    # Get subfunction code with size limit
                    sub_cfunc = ida_hexrays.decompile(called_func)
                    if sub_cfunc:
                        sub_code = str(sub_cfunc)
                        sub_lines = sub_code.split('\n')
                        if len(sub_lines) > MAX_SUBFUNCTION_LINES:
                            print(f"[WARNING] Subfunction {sub_name} is large ({len(sub_lines)} lines). Truncating to {MAX_SUBFUNCTION_LINES} lines.")
                            sub_code = '\n'.join(sub_lines[:MAX_SUBFUNCTION_LINES] + ['// ... (truncated) ...'])
                    else:
                        sub_code = "// Could not decompile subfunction"
                    
                    subfuncs.append({
                        "address": sub_addr,
                        "name": sub_name,
                        "type": "sub_function",
                        "code": sub_code
                    })
                else:
                    print(f"- No valid function at {hex(sub_addr)}")
            else:
                if sub_addr == ida_idaapi.BADADDR:
                    print("- Invalid address")
                elif sub_addr in seen_funcs:
                    print("- Already seen")
                elif sub_addr == func_addr:
                    print("- Self reference")
        
        print(f"\nFinal subfunctions list: {len(subfuncs)}")
        for sub in subfuncs:
            print(f"- {sub['name']} at {hex(sub['address'])}")
        
        print("="*80)
        
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
        log_debug(f"Error getting function info for {hex(func_addr)}: {str(e)}")
        return None

def create_function_text(func_info, include_subfuncs=True):
    """Create text representation of a function with token counting."""
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
        
        # Build the subfunctions section if requested
        subfuncs_text = []
        if include_subfuncs:
            for sub in func_info.get('subfunctions', []):
                sub_func = get_function_info(sub['address'])
                if sub_func:
                    subfuncs_text.append(f"- {sub['name']} at {hex(sub['address'])}:")
                    # Only include first 100 lines of subfunction code to save tokens
                    sub_code = str(sub_func.get('code', '')).split('\n')[:100]
                    subfuncs_text.append('\n'.join(sub_code))
        
        # Create the function text
        func_text = (
            f"\n=== Function {func_info['name']} at {hex(func_info['address'])} ===\n"
            f"Variables:\n{chr(10).join(variables_text)}\n\n"
            f"Code:\n{code}\n\n"
            f"Called by: {[hex(x) for x in func_info['called_by']]}\n"
            f"Calls to: {[hex(x) for x in func_info['calls']]}\n\n"
        )
        
        # Add subfunctions if they exist and were requested
        if subfuncs_text and include_subfuncs:
            func_text += f"Sub-functions:\n{chr(10).join(subfuncs_text)}\n"
            
        return func_text
    except Exception as e:
        print(f"Error creating function text: {str(e)}")
        return ""

def comment_callback(address, view, response):
    """
    Callback that sets a comment at the given address.
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    print(f"\n[DEBUG] comment_callback called for address {hex(address)}")
    print(f"[DEBUG] View object present: {view is not None}")
    print(f"[DEBUG] Response length: {len(response)}")
    
    # Add the response as a comment in IDA, but preserve any existing non-rAIversing comment
    comment = idc.get_func_cmt(address, 0)
    print(f"[DEBUG] Existing comment: {comment}")
    
    # Remove any existing rAIversing comment sections
    if comment:
        comment = re.sub(
            r'----- Comment generated by rAIversing -----.*?----------------------------------------\s*',
            "",
            comment,
            flags=re.DOTALL)
        comment = comment.strip()
        print(f"[DEBUG] Comment after cleaning rAIversing section: {comment}")

    # Create the new comment
    new_comment = response.strip()
    if comment:
        new_comment += "\n\n" + comment
        
    print(f"[DEBUG] New comment to set: {new_comment}")
    success = idc.set_func_cmt(address, new_comment, 0)
    print(f"[DEBUG] set_func_cmt result: {success}")
    
    # Refresh the window so the comment is displayed properly
    if view:
        print("[DEBUG] Refreshing view")
        view.refresh_view(False)
    else:
        print("[DEBUG] No view to refresh")

def rename_callback(address, view, response, retries=0):
    """
    Callback that extracts a JSON array of old names and new names from the
    response and sets them in the pseudocode.
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from the model
    :param retries: The number of times that we received invalid JSON
    """
    print(f"\n[DEBUG] rename_callback called for address {hex(address)}")
    print(f"[DEBUG] View object present: {view is not None}")
    print(f"[DEBUG] Response: {response}")
    print(f"[DEBUG] Retries: {retries}")
    
    try:
        names = json.loads(response)
        print(f"[DEBUG] Parsed names: {names}")
    except json.JSONDecodeError as e:
        print(f"[DEBUG] Error parsing JSON response: {str(e)}")
        return

    # The rename function needs the start address of the function
    function = ida_funcs.get_func(address)
    if not function:
        print("[DEBUG] Could not get function")
        return
        
    function_addr = function.start_ea
    print(f"[DEBUG] Function start address: {hex(function_addr)}")

    # Get the decompiled function
    try:
        cfunc = ida_hexrays.decompile(function_addr)
        if not cfunc:
            print("[DEBUG] Could not decompile function")
            return
    except Exception as e:
        print(f"[DEBUG] Error decompiling function: {str(e)}")
        return

    # Create a map of old names to new names
    var_map = {}
    for old_name, new_name in names.items():
        # Skip if names are the same
        if old_name == new_name:
            continue
            
        # Skip empty or invalid names
        if not old_name or not new_name:
            continue
            
        # Validate the new name
        valid_name = ida_name.validate_name(new_name, ida_name.VNT_VISIBLE)
        if not valid_name:
            print(f"[DEBUG] Invalid name: {new_name}")
            continue
            
        # Add to map
        var_map[old_name] = valid_name

    if var_map:
        print(f"[DEBUG] Attempting to rename {len(var_map)} variables")
        changes = 0
        
        # First try to rename using direct lvar modification
        for lvar in cfunc.get_lvars():
            old_name = str(lvar.name)
            if old_name in var_map:
                new_name = var_map[old_name]
                print(f"[DEBUG] Attempting to rename {old_name} to {new_name}")
                
                try:
                    # Try to rename using the view if available
                    if view and hasattr(view, 'rename_lvar'):
                        if view.rename_lvar(lvar, new_name, True):
                            print(f"[DEBUG] Successfully renamed {old_name} to {new_name} using view")
                            changes += 1
                            continue
                    
                    # Try direct renaming
                    if hasattr(ida_hexrays, 'rename_lvar'):
                        if ida_hexrays.rename_lvar(function_addr, old_name, new_name):
                            print(f"[DEBUG] Successfully renamed {old_name} to {new_name} using rename_lvar")
                            changes += 1
                            continue
                    
                    # Try modifying the name directly
                    lvar.name = new_name
                    if str(lvar.name) == new_name:
                        print(f"[DEBUG] Successfully renamed {old_name} to {new_name} using direct assignment")
                        changes += 1
                    else:
                        print(f"[DEBUG] Failed to rename {old_name} to {new_name}")
                        
                except Exception as e:
                    print(f"[DEBUG] Error renaming {old_name}: {str(e)}")
        
        print(f"[DEBUG] Successfully renamed {changes} variables")
        
        # Refresh the pseudocode view
        if view:
            print("[DEBUG] Refreshing view")
            view.refresh_view(True)
        else:
            print("[DEBUG] No view to refresh")
            # Try to force a refresh of the decompiler
            try:
                cfunc.refresh_func_ctext()
            except:
                pass
    else:
        print("[DEBUG] No variables to rename")

    # Update possible names left in the function comment
    comment = idc.get_func_cmt(address, 0)
    print(f"\n[DEBUG] Current function comment: {comment}")
    if comment and var_map:
        print("[DEBUG] Updating variable names in comment")
        for old_name, new_name in var_map.items():
            comment = re.sub(r'\b%s\b' % old_name, new_name, comment)
        success = idc.set_func_cmt(address, comment, 0)
        print(f"[DEBUG] Updated comment set_func_cmt result: {success}")

    # Final refresh of the window
    if view:
        print("[DEBUG] Final view refresh")
        view.refresh_view(True)

def apply_improvements(results):
    """Apply improvements from parallel processing in a thread-safe manner."""
    print("\n[DEBUG] Starting apply_improvements")
    print(f"[DEBUG] Number of results to process: {len(results)}")
    improved = 0
    
    for result in results:
        if not result:
            print("[DEBUG] Skipping empty result")
            continue
            
        func_addr = result['func_addr']
        func_info = result['func_info']
        suggestions = result['suggestions']
        
        print(f"\n[DEBUG] Processing function at {hex(func_addr)}")
        print(f"[DEBUG] Current function name: {func_info['name']}")
        print(f"[DEBUG] Suggestions: {json.dumps(suggestions, indent=2)}")
        
        try:
            def update_ui():
                nonlocal improved
                
                print(f"\n[DEBUG] Starting UI update for {hex(func_addr)}")
                
                # Get the decompiler view for the function
                cfunc = None
                try:
                    cfunc = ida_hexrays.decompile(func_addr)
                    print("[DEBUG] Successfully decompiled function")
                except Exception as e:
                    print(f"[DEBUG] Could not decompile function: {str(e)}")
                    return
                
                # Get the decompiler widget
                widget = ida_kernwin.find_widget("Pseudocode-" + ida_funcs.get_func_name(func_addr))
                if widget:
                    print("[DEBUG] Found pseudocode widget")
                    vu = ida_hexrays.get_widget_vdui(widget)
                    print(f"[DEBUG] Got widget VDUI: {vu is not None}")
                else:
                    print("[DEBUG] No pseudocode widget found")
                    vu = None
                
                # Update function name
                new_name = suggestions.get("function_name")
                if new_name:
                    # Remove any existing address suffix
                    base_name = re.sub(r'_[0-9a-fA-F]+$', '', new_name)
                    current_base_name = re.sub(r'_[0-9a-fA-F]+$', '', func_info['name'])
                    
                    if base_name != current_base_name:
                        new_name_with_addr = f"{base_name}_{hex(func_addr)[2:]}"
                        print(f"[DEBUG] Attempting to rename function to: {new_name_with_addr}")
                        if ida_name.force_name(func_addr, new_name_with_addr):
                            print(f"[DEBUG] Successfully renamed function to: {new_name_with_addr}")
                            improved += 1
                        else:
                            print(f"[DEBUG] Failed to rename function to: {new_name_with_addr}")
                
                # Add function description and analysis as comments
                if suggestions.get("description") or suggestions.get("analysis"):
                    print("[DEBUG] Processing description and analysis")
                    description = suggestions.get("description", "")
                    analysis = suggestions.get("analysis", "")
                    
                    # Format the comment
                    comment = ""
                    if description:
                        comment = description
                    if analysis:
                        if comment:
                            comment += "\n\n"
                        comment += analysis
                    
                    if comment:
                        print(f"[DEBUG] Calling comment_callback with comment length: {len(comment)}")
                        # Use Gepetto's comment callback
                        comment_callback(func_addr, vu, comment)
                        improved += 1
                
                # Handle variable renaming
                if cfunc and suggestions.get("variables"):
                    print("\n[DEBUG] Processing variable renames")
                    # Convert variables to Gepetto's format
                    var_dict = {}
                    
                    # Get all local variables from the decompiled function
                    all_lvars = {}
                    try:
                        if vu:
                            all_lvars = {str(lvar.name): lvar for lvar in vu.cfunc.lvars}
                        else:
                            all_lvars = {str(lvar.name): lvar for lvar in cfunc.get_lvars()}
                        print(f"[DEBUG] Found local variables: {list(all_lvars.keys())}")
                    except Exception as e:
                        print(f"[DEBUG] Error getting local variables: {str(e)}")
                        all_lvars = {}
                    
                    # Process each variable suggestion
                    for var in suggestions["variables"]:
                        old_name = var.get("old_name")
                        new_name = var.get("new_name")
                        var_type = var.get("type")
                        explanation = var.get("explanation")
                        
                        if old_name and new_name and old_name != new_name:
                            print(f"[DEBUG] Processing variable: {old_name} -> {new_name} ({var_type})")
                            print(f"[DEBUG] Explanation: {explanation}")
                            
                            # Try to find the variable in different ways
                            found = False
                            
                            # Check in local variables
                            if old_name in all_lvars:
                                print(f"[DEBUG] Found variable {old_name} in local variables")
                                var_dict[old_name] = new_name
                                found = True
                            
                            # Check if it's a function argument
                            if not found and cfunc:
                                try:
                                    for arg in cfunc.arguments:
                                        if str(arg.name) == old_name:
                                            print(f"[DEBUG] Found variable {old_name} in function arguments")
                                            var_dict[old_name] = new_name
                                            found = True
                                            break
                                except:
                                    pass
                            
                            if not found:
                                print(f"[DEBUG] Variable {old_name} not found in function")
                    
                    if var_dict:
                        print(f"[DEBUG] Calling rename_callback with {len(var_dict)} variables")
                        print(f"[DEBUG] Variable renames: {json.dumps(var_dict, indent=2)}")
                        # Use Gepetto's rename callback
                        rename_callback(func_addr, vu, json.dumps(var_dict), 0)
                        improved += 1
                    else:
                        print("[DEBUG] No variables to rename")
                        
                # Handle subfunction renaming if present
                if suggestions.get("subfunctions"):
                    print("\n[DEBUG] Processing subfunction renames")
                    for subfunc in suggestions["subfunctions"]:
                        orig_name = subfunc.get("name")
                        new_name = subfunc.get("suggested_name")
                        if orig_name and new_name and orig_name != new_name:
                            print(f"[DEBUG] Processing subfunction rename: {orig_name} -> {new_name}")
                            # Get the subfunction address
                            sub_addr = ida_name.get_name_ea(ida_idaapi.BADADDR, orig_name)
                            if sub_addr != ida_idaapi.BADADDR:
                                new_name_with_addr = f"{new_name}_{hex(sub_addr)[2:]}"
                                print(f"[DEBUG] Attempting to rename subfunction to: {new_name_with_addr}")
                                if ida_name.force_name(sub_addr, new_name_with_addr):
                                    print(f"[DEBUG] Successfully renamed subfunction to: {new_name_with_addr}")
                                    improved += 1
                                else:
                                    print(f"[DEBUG] Failed to rename subfunction to: {new_name_with_addr}")
                            else:
                                print(f"[DEBUG] Could not find subfunction address for: {orig_name}")
            
            print(f"[DEBUG] Executing UI update for {hex(func_addr)} in main thread")
            # Execute UI updates in main thread with MFF_WRITE flag
            ida_kernwin.execute_sync(update_ui, ida_kernwin.MFF_WRITE)
            
        except Exception as e:
            print(f"[DEBUG] Error applying improvements for {hex(func_addr)}: {str(e)}")
            print(f"[DEBUG] Error traceback: {traceback.format_exc()}")
            
    print(f"\n[DEBUG] Completed apply_improvements. Total improvements: {improved}")
    return improved

def save_database_sync():
    """Save the database in a thread-safe way."""
    try:
        # Get the current database path
        path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not path:
            print("[WARNING] Could not get current database path")
            return False
            
        # Save the database
        if ida_loader.save_database(path, 0):
            print("Database saved successfully")
            return True
        else:
            print("[ERROR] Failed to save database")
            return False
    except Exception as e:
        print(f"[ERROR] Error saving database: {str(e)}")
        return False

def improve_all_functions():
    """Improve all function names in the binary using parallel processing."""
    global g_analysis_cancelled
    g_analysis_cancelled = False
    
    # Enable batch mode to suppress dialogs
    old_batch = ida_kernwin.cvar.batch
    ida_kernwin.cvar.batch = 1
    
    try:
        ui = AnalysisUI()
        functions = get_analysis_order()
        ui.progress.total_funcs = len(functions)
        
        ui.show_wait_box(f"Analyzing {len(functions)} functions...")
        print(f"\nFound {len(functions)} functions to analyze")
        print(f"Analyzing in parallel batches (up to {MAX_THREADS} threads, {BATCH_SIZE} functions per batch)")
        
        visited = set()
        results = []
        
        # Create batches of functions
        function_batches = [functions[i:i + BATCH_SIZE] for i in range(0, len(functions), BATCH_SIZE)]
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            # Submit function batches for processing
            future_to_batch = {
                executor.submit(process_function_batch, batch, ui, visited, 0): batch
                for batch in function_batches
            }
            
            # Process results as they complete
            completed = 0
            last_save = 0
            for future in as_completed(future_to_batch):
                batch = future_to_batch[future]
                try:
                    batch_results = future.result()
                    if batch_results:
                        results.extend(batch_results)
                except Exception as e:
                    print(f"Error processing batch: {str(e)}")
                    
                completed += len(batch)
                progress = (completed * 100) / len(functions)
                ui.replace_wait_box(f"Analyzed {completed}/{len(functions)} functions ({progress:.1f}%)...")
                
                # Auto-save every SAVE_INTERVAL functions
                if completed - last_save >= SAVE_INTERVAL:
                    print(f"\nAuto-saving database after {completed} functions...")
                    ida_kernwin.execute_sync(save_database_sync, ida_kernwin.MFF_FAST)
                    last_save = completed
                    print("Database saved successfully")
                
                if g_analysis_cancelled:
                    print("\nAnalysis cancelled by user")
                    break
                    
        # Apply all improvements in the main thread
        improved = apply_improvements(results)
        
        # Final save after all improvements
        print("\nSaving final changes to database...")
        ida_kernwin.execute_sync(save_database_sync, ida_kernwin.MFF_FAST)
        print("Database saved successfully")
        
        print(f"\nCompleted! Improved {improved} out of {len(functions)} functions")
        
    finally:
        # Restore batch mode
        ida_kernwin.cvar.batch = old_batch
        ui.hide_wait_box()

def process_function_batch(batch, ui, visited, depth=0):
    """Process a batch of functions in parallel."""
    print(f"\n[DEBUG] Processing batch of {len(batch)} functions")
    results = []
    
    def get_func_info_sync(func_addr):
        """Get function info in the main thread."""
        result = []
        def sync_func():
            info = get_function_info(func_addr)
            result.append(info)
        ida_kernwin.execute_sync(sync_func, ida_kernwin.MFF_FAST)
        return result[0] if result else None
    
    for func_addr in batch:
        if g_analysis_cancelled:
            break
            
        if func_addr in visited:
            continue
            
        func_info = get_func_info_sync(func_addr)
        if not func_info:
            continue
            
        print(f"\n[DEBUG] Getting suggestions for {func_info['name']} at {hex(func_addr)}")
        suggestions = analyze_function_with_ai(func_info)
        
        if suggestions:
            results.append({
                'func_addr': func_addr,
                'func_info': func_info,
                'suggestions': suggestions
            })
            
        if ui:
            ui.progress.update(func_info['name'])
            
    return results

def improve_current_function():
    """Improve the function under the cursor."""
    current_addr = idc.get_screen_ea()
    func = ida_funcs.get_func(current_addr)
    
    if not func:
        print("No function at cursor")
        return
        
    ui = AnalysisUI()
    ui.progress.total_funcs = 1
    ui.show_wait_box("Analyzing current function...")
    
    try:
        # Process single function and apply improvements
        batch_results = process_function_batch([func.start_ea], ui, set())
        if batch_results:
            print("\n[DEBUG] Applying improvements from batch results")
            apply_improvements(batch_results)
    finally:
        ui.hide_wait_box()

def improve_next_n_functions(n):
    """Improve the next N functions starting from the current cursor position."""
    current_addr = idc.get_screen_ea()
    
    # Get all functions and find the current one's index
    all_functions = list(idautils.Functions())
    try:
        current_idx = next(i for i, addr in enumerate(all_functions) if addr >= current_addr)
    except StopIteration:
        print(f"No functions found after current position")
        return
        
    # Get the next N functions
    next_functions = all_functions[current_idx:current_idx + n]
    if not next_functions:
        print(f"No more functions to analyze")
        return
        
    print(f"\nAnalyzing next {len(next_functions)} functions starting from {hex(next_functions[0])}")
    
    # Create a mini version of improve_all_functions for this batch
    global g_analysis_cancelled
    g_analysis_cancelled = False
    
    # Enable batch mode to suppress dialogs
    old_batch = ida_kernwin.cvar.batch
    ida_kernwin.cvar.batch = 1
    
    try:
        ui = AnalysisUI()
        ui.progress.total_funcs = len(next_functions)
        
        ui.show_wait_box(f"Analyzing {len(next_functions)} functions...")
        
        visited = set()
        results = []
        
        # Create batches of functions
        function_batches = [next_functions[i:i + INITIAL_BATCH_SIZE] 
                          for i in range(0, len(next_functions), INITIAL_BATCH_SIZE)]
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            # Submit function batches for processing
            future_to_batch = {
                executor.submit(process_function_batch, batch, ui, visited, 0): batch
                for batch in function_batches
            }
            
            # Process results as they complete
            completed = 0
            last_save = 0
            for future in as_completed(future_to_batch):
                batch = future_to_batch[future]
                try:
                    batch_results = future.result()
                    if batch_results:
                        results.extend(batch_results)
                except Exception as e:
                    print(f"Error processing batch: {str(e)}")
                    
                completed += len(batch)
                progress = (completed * 100) / len(next_functions)
                ui.replace_wait_box(f"Analyzed {completed}/{len(next_functions)} functions ({progress:.1f}%)...")
                
                # Auto-save every SAVE_INTERVAL functions
                if completed - last_save >= SAVE_INTERVAL:
                    print(f"\nAuto-saving database after {completed} functions...")
                    ida_kernwin.execute_sync(save_database_sync, ida_kernwin.MFF_FAST)
                    last_save = completed
                    print("Database saved successfully")
                
                if g_analysis_cancelled:
                    print("\nAnalysis cancelled by user")
                    break
                    
        # Apply all improvements in the main thread
        improved = apply_improvements(results)
        
        # Final save after all improvements
        print("\nSaving final changes to database...")
        ida_kernwin.execute_sync(save_database_sync, ida_kernwin.MFF_FAST)
        print("Database saved successfully")
        
        print(f"\nCompleted! Improved {improved} out of {len(next_functions)} functions")
        
        # Move cursor to the next function after the last analyzed one
        if len(next_functions) > 0:
            next_addr = next_functions[-1]
            next_func = ida_funcs.get_next_func(next_addr)
            if next_func:
                ida_kernwin.jumpto(next_func.start_ea)
        
    finally:
        # Restore batch mode
        ida_kernwin.cvar.batch = old_batch
        ui.hide_wait_box()

# Create menu items
class RaiversingActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, callback):
        ida_kernwin.action_handler_t.__init__(self)
        self.callback = callback
        
    def activate(self, ctx):
        self.callback()
        return 1
        
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

def register_menu():
    """Register menu items."""
    try:
        # Create the menu path first
        menu_path = "Edit/rAIversing/"
        
        # First unregister any existing actions
        action_ids = [
            "raiversing:improve_all",
            "raiversing:improve_current",
            "raiversing:improve_next_10",
            "raiversing:improve_next_50",
            "raiversing:improve_next_100",
            "raiversing:improve_next_1000"
        ]
        
        for action_id in action_ids:
            ida_kernwin.unregister_action(action_id)
            
        # Create menu items
        actions = [
            {
                "id": "raiversing:improve_all",
                "name": "Improve All Functions",
                "callback": improve_all_functions,
                "shortcut": "Ctrl+Shift+A",
                "tooltip": "Analyze all functions",
                "menu_path": menu_path + "Improve All Functions"
            },
            {
                "id": "raiversing:improve_current",
                "name": "Improve Current Function",
                "callback": improve_current_function,
                "shortcut": "Ctrl+Shift+C",
                "tooltip": "Analyze function under cursor",
                "menu_path": menu_path + "Improve Current Function"
            },
            {
                "id": "raiversing:improve_next_10",
                "name": "Improve Next 10 Functions",
                "callback": lambda: improve_next_n_functions(10),
                "shortcut": "Ctrl+Shift+1",
                "tooltip": "Analyze next 10 functions from cursor",
                "menu_path": menu_path + "Improve Next 10 Functions"
            },
            {
                "id": "raiversing:improve_next_50",
                "name": "Improve Next 50 Functions",
                "callback": lambda: improve_next_n_functions(50),
                "shortcut": "Ctrl+Shift+5",
                "tooltip": "Analyze next 50 functions from cursor",
                "menu_path": menu_path + "Improve Next 50 Functions"
            },
            {
                "id": "raiversing:improve_next_100",
                "name": "Improve Next 100 Functions",
                "callback": lambda: improve_next_n_functions(100),
                "shortcut": "Ctrl+Shift+2",
                "tooltip": "Analyze next 100 functions from cursor",
                "menu_path": menu_path + "Improve Next 100 Functions"
            },
            {
                "id": "raiversing:improve_next_1000",
                "name": "Improve Next 1000 Functions",
                "callback": lambda: improve_next_n_functions(1000),
                "shortcut": "Ctrl+Shift+3",
                "tooltip": "Analyze next 1000 functions from cursor",
                "menu_path": menu_path + "Improve Next 1000 Functions"
            }
        ]
        
        for action in actions:
            action_desc = ida_kernwin.action_desc_t(
                action["id"],
                action["name"],
                RaiversingActionHandler(action["callback"]),
                action["shortcut"],
                action["tooltip"],
                -1
            )
            
            if ida_kernwin.register_action(action_desc):
                print(f"Registered action: {action['id']}")
                if ida_kernwin.attach_action_to_menu(
                    action["menu_path"],
                    action["id"],
                    ida_kernwin.SETMENU_APP
                ):
                    print(f"Attached {action['id']} to menu")
                else:
                    print(f"Failed to attach {action['id']} to menu")
            else:
                print(f"Failed to register action: {action['id']}")
                
        return True
    except Exception as e:
        print(f"Error registering menu: {str(e)}")
        return False

# This will be called when the script is run
def SCRIPT_ENTRY():
    print("\nInitializing rAIversing script...")
    if register_menu():
        print("\nrAIversing script loaded successfully!")
        print("Available commands:")
        print("- improve_all_functions() - Analyze all functions")
        print("- improve_current_function() - Analyze function under cursor")
        print("- Use Edit > rAIversing menu")
        
        # Make functions available in global namespace
        import sys
        module = sys.modules[__name__]
        setattr(module, 'improve_all_functions', improve_all_functions)
        setattr(module, 'improve_current_function', improve_current_function)
    else:
        print("Failed to initialize rAIversing script")

# Entry point when run as script
if __name__ == '__main__':
    SCRIPT_ENTRY() 