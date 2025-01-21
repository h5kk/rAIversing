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

# Initialize OpenAI client
client = OpenAI(api_key="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")  # Replace with your actual API key securely

# Global state for cancellation
g_analysis_cancelled = False

class AnalysisProgress:
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

def build_call_graph():
    """Build a call graph of all functions."""
    calls = defaultdict(set)  # who calls who
    called_by = defaultdict(set)  # who is called by who
    
    for func_addr in idautils.Functions():
        func = ida_funcs.get_func(func_addr)
        if not func:
            continue
            
        # Get all calls from this function
        for xref in idautils.XrefsFrom(func_addr, 0):
            if xref.type in [ida_kernwin.fl_CN, ida_kernwin.fl_CF]:  # Call Near or Call Far
                called_func = ida_funcs.get_func(xref.to)
                if called_func:
                    calls[func_addr].add(called_func.start_ea)
                    called_by[called_func.start_ea].add(func_addr)
                    
    return calls, called_by

def get_analysis_order():
    """Get functions in bottom-up order (callees before callers)."""
    calls, called_by = build_call_graph()
    visited = set()
    order = []
    
    def visit(func_addr):
        if func_addr in visited:
            return
        visited.add(func_addr)
        
        # First visit all functions this one calls
        for callee in calls[func_addr]:
            visit(callee)
            
        order.append(func_addr)
    
    # Visit all functions
    for func_addr in idautils.Functions():
        visit(func_addr)
        
    return order

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
                    subfuncs.append({
                        "address": sub_addr,
                        "name": sub_name,
                        "type": "sub_function"
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

def analyze_function_with_ai(func_info):
    """Analyze function using OpenAI API."""
    if not func_info:
        return None
        
    try:
        # Clean up the code for better formatting
        code = func_info['code'].replace('\t', '    ')
        
        # Get information about subfunctions
        subfunction_info = []
        for sub in func_info.get('subfunctions', []):
            sub_func = get_function_info(sub['address'])
            if sub_func:
                subfunction_info.append({
                    'name': sub['name'],
                    'code': str(sub_func.get('code', '')),
                    'address': hex(sub['address'])
                })
        
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
        for sub in subfunction_info:
            subfuncs_text.append(f"- {sub['name']} at {sub['address']}:")
            subfuncs_text.append(sub['code'])
        
        # Create the prompt using concatenation instead of a single f-string
        prompt = (
            "Analyze this decompiled C++ function and its subfunctions.\n\n"
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
            '            "variables": [\n'
            "                {\n"
            '                    "old_name": "original_var",\n'
            '                    "new_name": "new_var",\n'
            '                    "explanation": "reason for renaming",\n'
            '                    "type": "var_type"\n'
            "                }\n"
            "            ],\n"
            '            "analysis": "Detailed analysis of the subfunction"\n'
            "        }\n"
            "    ]\n"
            "}\n\n"
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
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a reverse engineering assistant specialized in analyzing C++ code. You provide analysis in strict JSON format with no additional text. Pay special attention to security implications, buffer usage, and error handling. When suggesting names:\n1. Be specific and descriptive\n2. Use standard prefixes/suffixes\n3. Indicate types where helpful\n4. Keep existing good names\n5. Follow C++ naming conventions"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=4000
            )
        
        # Log raw response for debugging
        raw_response = response.choices[0].message.content
        print("AI Response:", raw_response)
        
        try:
            suggestions = json.loads(raw_response)
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
        ida_kernwin.execute_sync(update_ui, ida_kernwin.MFF_FAST)

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

def improve_all_functions():
    """Improve all function names in the binary."""
    global g_analysis_cancelled
    g_analysis_cancelled = False
    
    # Enable batch mode to suppress dialogs
    old_batch = ida_kernwin.cvar.batch
    ida_kernwin.cvar.batch = 1
    
    try:
        ui = AnalysisUI()
        functions = get_analysis_order()  # Get functions in bottom-up order
        ui.progress.total_funcs = len(functions)
        
        ui.show_wait_box(f"Analyzing {len(functions)} functions...")
        print(f"\nFound {len(functions)} functions to analyze")
        print("Analyzing in bottom-up order (callees before callers)")
        
        improved = 0
        for i, func_addr in enumerate(functions, 1):
            if g_analysis_cancelled:
                print("\nAnalysis cancelled by user")
                break
                
            print(f"\nProcessing function {i}/{len(functions)}")
            if improve_function(func_addr, ui):
                improved += 1
                
            # Update progress every 10 functions
            if i % 10 == 0:
                progress = ui.progress.get_progress()
                ui.replace_wait_box(f"Analyzed {i}/{len(functions)} functions ({progress:.1f}%)...")
                
        print(f"\nCompleted! Improved {improved} out of {len(functions)} functions")
        
    finally:
        # Restore batch mode
        ida_kernwin.cvar.batch = old_batch
        ui.hide_wait_box()

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
        improve_function(func.start_ea, ui)
    finally:
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
        for action_id in ["raiversing:improve_all", "raiversing:improve_current"]:
            ida_kernwin.unregister_action(action_id)

        # Create menu items
        actions = [
            {
                "id": "raiversing:improve_all",
                "name": "Improve All Functions",
                "callback": improve_all_functions,
                "shortcut": "",
                "tooltip": "Analyze all functions",
                "menu_path": menu_path + "Improve All Functions"
            },
            {
                "id": "raiversing:improve_current",
                "name": "Improve Current Function",
                "callback": improve_current_function,
                "shortcut": "",
                "tooltip": "Analyze function under cursor",
                "menu_path": menu_path + "Improve Current Function"
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