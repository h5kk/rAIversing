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
import ida_bytes
import ida_nalt

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

# Analysis categories for enhanced understanding
ANALYSIS_CATEGORIES = {
    # "security": [
    #     "buffer overflows",
    #     "integer overflows",
    #     "memory leaks",
    #     "null pointer dereferences",
    #     "use-after-free",
    #     "format string vulnerabilities",
    #     "input validation"
    # ],
    # "performance": [
    #     "algorithmic complexity",
    #     "memory usage",
    #     "loop efficiency",
    #     "resource management",
    #     "caching behavior"
    # ],
    # "code_quality": [
    #     "error handling",
    #     "resource cleanup",
    #     "code organization",
    #     "modularity",
    #     "reusability"
    # ],
    "class_structure": [
        "class_hierarchy",
        "inheritance_relationships",
        "virtual_methods",
        "member_variables",
        "member_functions",
        "access_modifiers",
        "vtable_layout",
        "constructor_destructor_patterns",
        "class_dependencies",
        "instance_relationships"
    ],
    "functionality": [
        "main purpose",
        "edge cases",
        "input/output behavior",
        "state management",
        "error conditions"
    ]
}

# Add game-specific analysis categories
GAME_FEATURES = {
    "player_systems": [
        "character_stats",
        "inventory",
        "equipment",
        "skills_abilities",
        "quests",
        "achievements",
        "character_customization",
        "player_progression",
        "experience_points",
        "levels"
    ],
    "combat_systems": [
        "damage_calculation",
        "combat_mechanics",
        "skill_effects",
        "buffs_debuffs",
        "status_effects",
        "combat_states",
        "targeting",
        "hit_detection",
        "combat_animations"
    ],
    "networking": [
        "client_server_sync",
        "player_position",
        "state_replication",
        "lag_compensation",
        "packet_handling",
        "server_commands",
        "client_updates"
    ],
    "world_systems": [
        "map_management",
        "zone_transitions",
        "world_state",
        "environment_effects",
        "npc_management",
        "spawn_systems",
        "world_events"
    ],
    "ui_systems": [
        "hud_elements",
        "menus",
        "chat_system",
        "inventory_ui",
        "character_window",
        "skill_interface",
        "quest_tracking"
    ],
    "game_logic": [
        "game_states",
        "event_handling",
        "interaction_systems",
        "quest_logic",
        "dialogue_systems",
        "trading_systems",
        "party_systems",
        "guild_systems"
    ],
    "data_management": [
        "save_load",
        "character_data",
        "inventory_data",
        "quest_data",
        "world_data",
        "configuration"
    ]
}

# Common MMORPG naming patterns
MMORPG_NAMING_PATTERNS = {
    "player": [
        "Player", "Character", "Avatar", "Unit", "Entity", "Actor", "Char"
    ],
    "inventory": [
        "Item", "Inventory", "Equipment", "Gear", "Loot", "Storage", "Container"
    ],
    "combat": [
        "Combat", "Battle", "Fight", "Damage", "Attack", "Defense", "Skill", "Spell", "Ability"
    ],
    "network": [
        "Net", "Packet", "Sync", "Update", "Server", "Client", "Connection", "Session"
    ],
    "world": [
        "World", "Map", "Zone", "Area", "Region", "Scene", "Location", "Position"
    ],
    "ui": [
        "Window", "Panel", "Menu", "HUD", "Interface", "Display", "Screen", "UI"
    ],
    "game": [
        "Game", "State", "Manager", "Controller", "Handler", "System", "Module"
    ],
    "data": [
        "Data", "Info", "Stats", "Config", "Settings", "Properties", "Attributes"
    ]
}

# Enhanced JSON schema with game-specific analysis
ANALYSIS_SCHEMA = {
    "function_name": "suggested_function_name",
    "description": {
        "summary": "Brief description of what the function does",
        "purpose": "Detailed explanation of the function's purpose",
        "inputs": "Description of input parameters and their purposes",
        "outputs": "Description of return values and side effects",
        "assumptions": "Any assumptions made by the function",
        "game_feature": "Which game feature or system this function belongs to"
    },
    "class_info": {
        "class_name": "Name of the class this function belongs to",
        "parent_classes": ["List of parent classes in inheritance hierarchy"],
        "class_type": "Type of class (base, derived, interface, etc.)",
        "member_type": "Type of member (constructor, destructor, virtual method, etc.)",
        "access_level": "Public/Private/Protected",
        "virtual_info": {
            "is_virtual": "Whether this is a virtual method",
            "vtable_offset": "Offset in the vtable if virtual",
            "override_info": "Information about what this overrides"
        },
        "related_members": [
            {
                "name": "Name of related member",
                "type": "Type of the member",
                "relationship": "How it relates to this function",
                "access": "Access level"
            }
        ]
    },
    "variables": [
        {
            "old_name": "original_variable_name",
            "new_name": "suggested_variable_name",
            "explanation": "why this name is better",
            "type": "variable_type",
            "purpose": "what this variable is used for",
            "scope": "where this variable is used",
            "constraints": "any constraints or assumptions about the variable",
            "class_context": "how this variable relates to class members/state"
        }
    ],
    "analysis": {
        "class_structure": {
            "hierarchy": "Description of class inheritance and relationships",
            "member_analysis": "Analysis of member variables and functions used",
            "virtual_analysis": "Analysis of virtual method behavior if applicable",
            "state_management": "How the function manages class state",
            "inheritance_impact": "How inheritance affects this function's behavior"
        },
        # "security": {
        #     "vulnerabilities": "Potential security issues",
        #     "mitigations": "Existing security measures",
        #     "recommendations": "Security improvement suggestions",
        #     "game_specific": "Game-specific security considerations"
        # },
        # "performance": {
        #     "complexity": "Time and space complexity analysis",
        #     "bottlenecks": "Performance bottlenecks",
        #     "optimizations": "Potential optimizations",
        #     "game_impact": "Impact on game performance"
        # },
        # "code_quality": {
        #     "strengths": "Well-designed aspects of the code",
        #     "weaknesses": "Areas that could be improved",
        #     "recommendations": "Suggested improvements",
        #     "maintainability": "Long-term maintenance considerations"
        # },
        "functionality": {
            "main_flow": "Description of the main execution path",
            "edge_cases": "Handling of edge cases and errors",
            "dependencies": "External dependencies and assumptions",
            "side_effects": "Any side effects or state changes",
            "game_states": "Impact on game state"
        }
    },
    "subfunctions": [
        {
            "name": "original_subfunction_name",
            "suggested_name": "better_name",
            "purpose": "what this subfunction does",
            "variables": [],
            "class_context": {
                "member_access": "What class members this subfunction accesses",
                "state_changes": "How it affects class state",
                "inheritance_role": "Role in inheritance hierarchy if relevant"
            },
            "analysis": {
                "role": "How this subfunction contributes to the main function",
                "dependencies": "What this subfunction depends on",
                "improvements": "Suggested improvements"
            }
        }
    ]
}

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

def get_rtti_info(addr):
    """Get RTTI information for a given address."""
    try:
        # Try to get RTTI info using various methods
        rtti_info = {
            "class_name": None,
            "parent_classes": [],
            "vtable_addr": None,
            "type_descriptor": None
        }
        
        # Try to get RTTI type descriptor
        # Look for common RTTI patterns in IDA
        possible_rtti = []
        
        # Look for vtable references
        refs = list(idautils.XrefsTo(addr))
        for ref in refs:
            ref_addr = ref.frm
            # Look for typical vtable patterns
            vtable_start = ref_addr - 16  # Typical offset for MSVC
            
            # Try to read potential RTTI pointer
            try:
                rtti_ptr = ida_bytes.get_qword(vtable_start)
                if rtti_ptr and ida_bytes.is_loaded(rtti_ptr):
                    # Try to read type descriptor
                    type_desc = ida_bytes.get_strlit_contents(rtti_ptr + 16, -1, ida_nalt.STRTYPE_C)
                    if type_desc:
                        possible_rtti.append({
                            "vtable": vtable_start,
                            "rtti_ptr": rtti_ptr,
                            "type_desc": type_desc.decode('utf-8', errors='ignore')
                        })
            except:
                continue
        
        # Process found RTTI information
        for rtti in possible_rtti:
            type_desc = rtti["type_desc"]
            
            # Parse MSVC RTTI format
            # Typical format: .?AV<class_name>@@
            if type_desc.startswith(".?AV") or type_desc.startswith(".?AU"):
                class_name = type_desc[4:].rstrip("@")
                if class_name:
                    rtti_info["class_name"] = class_name
                    rtti_info["vtable_addr"] = rtti["vtable"]
                    rtti_info["type_descriptor"] = type_desc
                    break
        
        # Try to get parent class information
        if rtti_info["vtable_addr"]:
            # Read complete object locator
            try:
                col_ptr = ida_bytes.get_qword(rtti_info["vtable_addr"] - 8)
                if col_ptr and ida_bytes.is_loaded(col_ptr):
                    # Read hierarchy descriptor
                    hierarchy_ptr = ida_bytes.get_qword(col_ptr + 16)
                    if hierarchy_ptr and ida_bytes.is_loaded(hierarchy_ptr):
                        # Read number of base classes
                        num_bases = ida_bytes.get_dword(hierarchy_ptr + 8)
                        if num_bases > 0 and num_bases < 100:  # Sanity check
                            # Read base class array
                            base_array_ptr = ida_bytes.get_qword(hierarchy_ptr + 16)
                            if base_array_ptr and ida_bytes.is_loaded(base_array_ptr):
                                for i in range(num_bases):
                                    base_desc_ptr = ida_bytes.get_qword(base_array_ptr + i * 8)
                                    if base_desc_ptr and ida_bytes.is_loaded(base_desc_ptr):
                                        # Read type descriptor for base class
                                        type_desc_ptr = ida_bytes.get_qword(base_desc_ptr + 0)
                                        if type_desc_ptr and ida_bytes.is_loaded(type_desc_ptr):
                                            type_desc = ida_bytes.get_strlit_contents(type_desc_ptr + 16, -1, ida_nalt.STRTYPE_C)
                                            if type_desc:
                                                base_name = type_desc.decode('utf-8', errors='ignore')[4:].rstrip("@")
                                                if base_name and base_name != rtti_info["class_name"]:
                                                    rtti_info["parent_classes"].append(base_name)
            except:
                pass
                
        return rtti_info
    except Exception as e:
        print(f"Error getting RTTI info: {str(e)}")
        return None

def enhance_class_info(class_info, func_addr):
    """Enhance class information with RTTI data."""
    if not class_info:
        class_info = {
            "class_name": None,
            "parent_classes": [],
            "methods": [],
            "fields": [],
            "vtable": None,
            "is_virtual": False,
            "class_type": None
        }
    
    # Get RTTI information
    rtti_info = get_rtti_info(func_addr)
    if rtti_info:
        # Update class name if found in RTTI
        if rtti_info["class_name"]:
            class_info["class_name"] = rtti_info["class_name"]
            
        # Add any parent classes found in RTTI
        for parent in rtti_info["parent_classes"]:
            if parent not in class_info["parent_classes"]:
                class_info["parent_classes"].append(parent)
                
        # Update vtable information
        if rtti_info["vtable_addr"]:
            class_info["vtable"] = {
                "address": rtti_info["vtable_addr"],
                "type_descriptor": rtti_info["type_descriptor"],
                "methods": class_info.get("vtable", {}).get("methods", [])
            }
            
        # Mark as virtual if vtable found
        if rtti_info["vtable_addr"]:
            class_info["is_virtual"] = True
    
    return class_info

def get_class_info(func_addr):
    """Get enhanced class information for a function."""
    try:
        # Get basic class info first
        class_info = get_basic_class_info(func_addr)
        
        # Enhance with RTTI information
        class_info = enhance_class_info(class_info, func_addr)
        
        return class_info
    except Exception as e:
        print(f"Error getting class info: {str(e)}")
        return None

def get_basic_class_info(func_addr):
    """Get basic class information using IDA's type system."""
    try:
        # Original class info gathering code...
        func = ida_funcs.get_func(func_addr)
        if not func:
            return None
            
        cfunc = ida_hexrays.decompile(func)
        if not cfunc:
            return None
            
        class_info = {
            "class_name": None,
            "parent_classes": [],
            "methods": [],
            "fields": [],
            "vtable": None,
            "is_virtual": False,
            "class_type": None
        }
        
        # Check if this is a class method
        func_type = ida_typeinf.tinfo_t()
        if cfunc.type and cfunc.type.get_func_details(func_type):
            # Check if it's a member function
            if func_type.is_memfunc():
                # Get class type
                class_type = func_type.get_class_type()
                if class_type:
                    class_info["class_type"] = str(class_type)
                    class_info["class_name"] = class_type.get_type_name()
                    
                    # Check if virtual
                    class_info["is_virtual"] = func_type.is_vftable()
                    
                    # Try to get parent classes
                    parent = class_type
                    while parent:
                        parent = parent.get_base_class()
                        if parent:
                            parent_name = parent.get_type_name()
                            if parent_name:
                                class_info["parent_classes"].append(parent_name)
                    
                    # Get methods
                    for method in class_type.get_udt_methods():
                        method_info = {
                            "name": method.name,
                            "type": str(method.type),
                            "is_virtual": method.is_virtual(),
                            "access": method.get_access()
                        }
                        class_info["methods"].append(method_info)
                    
                    # Get fields
                    for field in class_type.get_udt_members():
                        field_info = {
                            "name": field.name,
                            "type": str(field.type),
                            "offset": field.offset,
                            "access": field.get_access()
                        }
                        class_info["fields"].append(field_info)
                    
                    # Try to find vtable
                    vtable = ida_typeinf.find_vtable_info(class_type)
                    if vtable:
                        class_info["vtable"] = {
                            "address": vtable.ea,
                            "size": vtable.size,
                            "methods": []
                        }
                        for i in range(vtable.size):
                            method_ea = ida_bytes.get_qword(vtable.ea + i * 8)
                            if method_ea:
                                method_name = ida_name.get_name(method_ea)
                                if method_name:
                                    class_info["vtable"]["methods"].append({
                                        "offset": i,
                                        "name": method_name,
                                        "address": method_ea
                                    })
        
        return class_info
    except Exception as e:
        print(f"Error getting basic class info: {str(e)}")
        return None

def format_class_name(class_name):
    """Format a class name to be more readable and accurate."""
    if not class_name:
        return ""
        
    # Remove common RTTI prefixes/suffixes
    name = class_name.strip()
    name = re.sub(r'^class\s+', '', name)
    name = re.sub(r'^struct\s+', '', name)
    
    # Handle template classes
    name = re.sub(r'<\s*>', '', name)  # Remove empty template brackets
    
    # Handle namespace separators
    name = name.replace("::", "_")
    
    # Remove invalid characters
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    
    # Remove multiple underscores
    name = re.sub(r'_+', '_', name)
    
    return name

def get_class_hierarchy_string(class_info):
    """Create an enhanced string representing the class hierarchy."""
    if not class_info or not class_info["class_name"]:
        return ""
        
    hierarchy = []
    
    # Add parent classes in reverse order (base class first)
    for parent in reversed(class_info["parent_classes"]):
        hierarchy.append(format_class_name(parent))
    
    # Add current class
    hierarchy.append(format_class_name(class_info["class_name"]))
    
    return "::".join(hierarchy)

def get_method_type_prefix(class_info, func_name):
    """Get appropriate prefix based on method type."""
    if not class_info:
        return ""
        
    # Check if it's a constructor
    if func_name.startswith("__ct"):
        return "ctor"
    # Check if it's a destructor
    elif func_name.startswith("__dt"):
        return "dtor"
    # Check if it's virtual
    elif class_info["is_virtual"]:
        return "virt"
    # Default to method
    else:
        return "method"

def analyze_function_with_ai(func_info):
    """Analyze function using OpenAI API with enhanced game-specific and class analysis."""
    if not func_info:
        return None
        
    try:
        # Get class information
        class_info = get_class_info(func_info['address'])
        if class_info:
            print(f"\nClass Information:")
            print(f"Class: {class_info['class_name']}")
            print(f"Parents: {', '.join(class_info['parent_classes'])}")
            print(f"Is Virtual: {class_info['is_virtual']}")
            
            # Add class info to function info
            func_info['class_info'] = class_info
            
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

        # Add class-specific analysis to the prompt
        class_analysis_prompt = ""
        if class_info and class_info["class_name"]:
            class_analysis_prompt = (
                "\nClass Analysis Instructions:\n"
                "1. Class Hierarchy Analysis:\n"
                f"   - Class: {class_info['class_name']}\n"
                f"   - Parent Classes: {', '.join(class_info['parent_classes'])}\n"
                f"   - Is Virtual: {class_info['is_virtual']}\n"
                "   - Analyze how this method fits into the class hierarchy\n"
                "   - Consider inheritance patterns and virtual method behavior\n"
                "   - Look for common game engine patterns in class design\n\n"
                "2. Method Analysis:\n"
                "   - Determine if this is a constructor, destructor, or regular method\n"
                "   - Analyze how it interacts with class fields\n"
                "   - Consider virtual method table implications\n"
                "   - Look for common method patterns in game engines\n\n"
                "3. Class Relationship Analysis:\n"
                "   - Analyze relationships with other game classes\n"
                "   - Consider component/entity patterns\n"
                "   - Look for game-specific design patterns\n\n"
            )

        # Create enhanced analysis prompt
        prompt = (
            "Analyze this decompiled C++ function from an MMORPG game. "
            "Provide a comprehensive analysis covering class structure, game features, security, performance, and functionality. "
            "Focus on understanding the code's purpose in the context of MMORPG game systems and class hierarchies.\n\n"
            
            f"Function Information:\n"
            f"- Name: {func_info['name']}\n"
            f"- Class: {get_class_hierarchy_string(class_info) if class_info and class_info['class_name'] else ''}\n"
            f"- Method Type: {get_method_type_prefix(class_info, func_info['name']) if class_info else ''}\n"
            f"- Variables:\n{chr(10).join(variables_text)}\n\n"
            
            f"Decompiled code:\n{code}\n\n"
            
            f"Called by: {[hex(x) for x in func_info['called_by']]}\n"
            f"Calls to: {[hex(x) for x in func_info['calls']]}\n\n"
            
            f"Sub-functions called:\n{chr(10).join(subfuncs_text)}\n\n"
            
            f"{class_analysis_prompt}\n"
            
            "Analysis Instructions:\n"
            "1. Game Feature Analysis:\n"
            "   - Identify which game system this function belongs to\n"
            "   - Analyze how it fits into the larger game architecture\n"
            "   - Consider interactions with other game systems\n"
            "   - Look for common MMORPG patterns and features\n\n"
            
            "2. Security Analysis:\n"
            "   - Identify potential exploits (duping, speed hacks, etc.)\n"
            "   - Check for proper validation of player actions\n"
            "   - Look for anti-cheat considerations\n"
            "   - Analyze network packet handling security\n\n"
            
            "3. Performance Analysis:\n"
            "   - Consider impact on game performance\n"
            "   - Look for network optimization opportunities\n"
            "   - Analyze memory usage patterns\n"
            "   - Check for scalability with many players\n\n"
            
            "4. Code Quality Analysis:\n"
            "   - Check for game-specific best practices\n"
            "   - Evaluate error handling for game states\n"
            "   - Look for proper cleanup of game resources\n"
            "   - Assess maintainability for live service\n\n"
            
            "5. Functionality Analysis:\n"
            "   - Understand impact on game mechanics\n"
            "   - Analyze player interaction flows\n"
            "   - Check for proper game state handling\n"
            "   - Consider multiplayer synchronization\n\n"
            
            "Game Systems to Consider:\n"
            + "\n".join(f"- {system.replace('_', ' ').title()}: {', '.join(features)}"
                     for system, features in GAME_FEATURES.items()) + "\n\n"
            
            "Common MMORPG Patterns:\n"
            + "\n".join(f"- {category}: {', '.join(patterns)}"
                     for category, patterns in MMORPG_NAMING_PATTERNS.items()) + "\n\n"
            
            "Provide the analysis in a JSON object with the following structure:\n"
            f"{json.dumps(ANALYSIS_SCHEMA, indent=2)}\n\n"
            
            "Naming Guidelines:\n"
            "1. Function names should:\n"
            "   - Start with a verb (calculate, process, validate)\n"
            "   - Include relevant game system (processInventoryItem, updatePlayerStats)\n"
            "   - Clearly indicate game-specific purpose\n"
            "   - Follow existing game naming patterns\n\n"
            
            "2. Variable names should:\n"
            "   - Use game-specific terminology\n"
            "   - Indicate type and game context\n"
            "   - Follow game system prefixes\n"
            "   - Be consistent with MMORPG conventions\n\n"
            
            "3. Parameter names should:\n"
            "   - Reflect game-specific purpose\n"
            "   - Indicate game state requirements\n"
            "   - Use standard game type prefixes\n\n"
            
            "4. Special cases:\n"
            "   - Player data: add player_ prefix\n"
            "   - Network data: add net_ prefix\n"
            "   - Game states: add state_ prefix\n"
            "   - UI elements: add ui_ prefix\n\n"
            
            "Focus on:\n"
            "- Understanding the function's role in game systems\n"
            "- Identifying game-specific patterns and features\n"
            "- Maintaining consistency with MMORPG conventions\n"
            "- Considering multiplayer and network aspects\n"
            "- Documenting game state dependencies\n"
        )

        # Use IDA's script timeout disabler during API call
        with ida_kernwin.disabled_script_timeout_t():
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert reverse engineering assistant specialized in analyzing C++ code for MMORPG games. "
                            "You have deep knowledge of common MMORPG architectures, game systems, and networking patterns. "
                            "You understand player systems, combat mechanics, inventory management, networking, and other key MMORPG features. "
                            "Your analysis should help developers understand how code fits into the larger game architecture. "
                            "Provide analysis in strict JSON format with no additional text, no markdown formatting, and no code block markers."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=MAX_TOKENS
            )
        
        # Process and validate response
        raw_response = response.choices[0].message.content
        print("AI Response:", raw_response)
        
        # Clean up the response
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
            if new_name:
                # Get enhanced class information
                class_info = get_class_info(func_addr)
                base_name = re.sub(r'_[0-9a-fA-F]+$', '', new_name)
                new_name_with_class = ""

                if class_info and class_info["class_name"]:
                    # Create class hierarchy string
                    hierarchy = get_class_hierarchy_string(class_info)
                    # Get method type prefix
                    method_prefix = get_method_type_prefix(class_info, func_info['name'])
                    
                    # Create new name with class information
                    if class_info["is_virtual"]:
                        new_name_with_class = f"{hierarchy}::virt_{base_name}_{hex(func_addr)[2:]}"
                    else:
                        new_name_with_class = f"{hierarchy}::{method_prefix}_{base_name}_{hex(func_addr)[2:]}"
                else:
                    # No class info, just add address
                    new_name_with_class = f"{base_name}_{hex(func_addr)[2:]}"
                    
                current_base_name = re.sub(r'_[0-9a-fA-F]+$', '', func_info['name'])
                
                if base_name != current_base_name:
                    print(f"[DEBUG] Attempting to rename function to: {new_name_with_class}")
                    if ida_name.force_name(func_addr, new_name_with_class):
                        print(f"[DEBUG] Successfully renamed function to: {new_name_with_class}")
                        improvements_count += 1
                    else:
                        print(f"[DEBUG] Failed to rename function to: {new_name_with_class}")

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
    """Enhanced callback that sets detailed comments at the given address."""
    print(f"\n[DEBUG] comment_callback called for address {hex(address)}")
    
    try:
        # Parse the response as JSON if it's a string
        if isinstance(response, str):
            try:
                analysis = json.loads(response)
            except json.JSONDecodeError:
                analysis = {"description": response}
        else:
            analysis = response
            
        # Format the comment with sections
        comment_parts = []
        
        # Add description section
        if isinstance(analysis.get("description"), dict):
            desc = analysis["description"]
            if desc.get("summary"):
                comment_parts.append("=== Summary ===")
                comment_parts.append(desc["summary"])
            if desc.get("purpose"):
                comment_parts.append("\n=== Purpose ===")
                comment_parts.append(desc["purpose"])
            if desc.get("inputs"):
                comment_parts.append("\n=== Inputs ===")
                comment_parts.append(desc["inputs"])
            if desc.get("outputs"):
                comment_parts.append("\n=== Outputs ===")
                comment_parts.append(desc["outputs"])
            if desc.get("assumptions"):
                comment_parts.append("\n=== Assumptions ===")
                comment_parts.append(desc["assumptions"])
        elif analysis.get("description"):
            comment_parts.append("=== Description ===")
            comment_parts.append(analysis["description"])
            
        # Add analysis sections
        if isinstance(analysis.get("analysis"), dict):
            analysis_data = analysis["analysis"]
            
            # Security analysis
            if "security" in analysis_data:
                comment_parts.append("\n=== Security Analysis ===")
                sec = analysis_data["security"]
                if sec.get("vulnerabilities"):
                    comment_parts.append("Vulnerabilities:")
                    comment_parts.append(sec["vulnerabilities"])
                if sec.get("mitigations"):
                    comment_parts.append("\nMitigations:")
                    comment_parts.append(sec["mitigations"])
                if sec.get("recommendations"):
                    comment_parts.append("\nRecommendations:")
                    comment_parts.append(sec["recommendations"])
                    
            # Performance analysis
            if "performance" in analysis_data:
                comment_parts.append("\n=== Performance Analysis ===")
                perf = analysis_data["performance"]
                if perf.get("complexity"):
                    comment_parts.append("Complexity:")
                    comment_parts.append(perf["complexity"])
                if perf.get("bottlenecks"):
                    comment_parts.append("\nBottlenecks:")
                    comment_parts.append(perf["bottlenecks"])
                if perf.get("optimizations"):
                    comment_parts.append("\nOptimizations:")
                    comment_parts.append(perf["optimizations"])
                    
            # Code quality analysis
            if "code_quality" in analysis_data:
                comment_parts.append("\n=== Code Quality Analysis ===")
                quality = analysis_data["code_quality"]
                if quality.get("strengths"):
                    comment_parts.append("Strengths:")
                    comment_parts.append(quality["strengths"])
                if quality.get("weaknesses"):
                    comment_parts.append("\nWeaknesses:")
                    comment_parts.append(quality["weaknesses"])
                if quality.get("recommendations"):
                    comment_parts.append("\nRecommendations:")
                    comment_parts.append(quality["recommendations"])
                    
            # Functionality analysis
            if "functionality" in analysis_data:
                comment_parts.append("\n=== Functionality Analysis ===")
                func = analysis_data["functionality"]
                if func.get("main_flow"):
                    comment_parts.append("Main Flow:")
                    comment_parts.append(func["main_flow"])
                if func.get("edge_cases"):
                    comment_parts.append("\nEdge Cases:")
                    comment_parts.append(func["edge_cases"])
                if func.get("dependencies"):
                    comment_parts.append("\nDependencies:")
                    comment_parts.append(func["dependencies"])
                if func.get("side_effects"):
                    comment_parts.append("\nSide Effects:")
                    comment_parts.append(func["side_effects"])
        elif analysis.get("analysis"):
            comment_parts.append("\n=== Analysis ===")
            comment_parts.append(analysis["analysis"])
            
        # Join all parts with proper formatting
        final_comment = "\n".join(comment_parts)
        
        # Set the comment in IDA
        success = idc.set_func_cmt(address, final_comment, 0)
        print(f"[DEBUG] set_func_cmt result: {success}")
        
        # Refresh the view
        if view:
            print("[DEBUG] Refreshing view")
            view.refresh_view(False)
            
    except Exception as e:
        print(f"[DEBUG] Error in comment_callback: {str(e)}")
        print(f"[DEBUG] Error traceback: {traceback.format_exc()}")

def rename_callback(address, view, response, retries=0):
    """
    Callback that extracts a JSON array of old names and new names from the
    response and sets them in the pseudocode.
    """
    print(f"\n[DEBUG] rename_callback called for address {hex(address)}")
    print(f"[DEBUG] View object present: {view is not None}")
    print(f"[DEBUG] Response: {response}")
    print(f"[DEBUG] Retries: {retries}")
    
    try:
        names = json.loads(response) if isinstance(response, str) else response
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

    # Create a map of old names to new names with type information
    var_map = {}
    
    # First pass: collect all variables from the function
    all_vars = {}
    for lvar in cfunc.get_lvars():
        var_name = str(lvar.name)
        if var_name.startswith('v'):  # Handle numbered variables (v1, v2, etc.)
            all_vars[var_name] = {
                'type': str(lvar.type()),
                'is_arg': lvar.is_arg_var,
                'location': str(lvar.location),
                'size': lvar.width
            }
    
    print(f"[DEBUG] Found variables in function: {all_vars}")
    
    # Second pass: try to intelligently rename variables based on type and usage
    for old_name, var_info in all_vars.items():
        # Skip if already in the map
        if old_name in names:
            continue
            
        var_type = var_info['type'].lower()
        
        # Try to generate a meaningful name based on type
        new_name = None
        
        if 'int' in var_type:
            if var_info['is_arg']:
                new_name = f"param_{old_name}"
            else:
                new_name = f"counter_{old_name}"
        elif 'bool' in var_type:
            new_name = f"flag_{old_name}"
        elif 'char' in var_type:
            new_name = f"char_{old_name}"
        elif 'ptr' in var_type or '*' in var_type:
            new_name = f"ptr_{old_name}"
        elif 'str' in var_type:
            new_name = f"str_{old_name}"
        elif '__int16' in var_type:
            new_name = f"short_{old_name}"
        elif 'byte' in var_type or '_BYTE' in var_type:
            new_name = f"byte_{old_name}"
        elif 'dword' in var_type or '_DWORD' in var_type:
            new_name = f"dword_{old_name}"
            
        if new_name:
            names[old_name] = new_name
            
    print(f"[DEBUG] Enhanced variable names: {names}")

    # Create the final variable map
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
    total_improvements = 0
    
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
                nonlocal total_improvements
                improvements_count = 0
                
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
                    # Get enhanced class information
                    class_info = get_class_info(func_addr)
                    base_name = re.sub(r'_[0-9a-fA-F]+$', '', new_name)
                    new_name_with_class = ""

                    if class_info and class_info["class_name"]:
                        # Create class hierarchy string
                        hierarchy = get_class_hierarchy_string(class_info)
                        # Get method type prefix
                        method_prefix = get_method_type_prefix(class_info, func_info['name'])
                        
                        # Create new name with class information
                        if class_info["is_virtual"]:
                            new_name_with_class = f"{hierarchy}::virt_{base_name}_{hex(func_addr)[2:]}"
                        else:
                            new_name_with_class = f"{hierarchy}::{method_prefix}_{base_name}_{hex(func_addr)[2:]}"
                    else:
                        # No class info, just add address
                        new_name_with_class = f"{base_name}_{hex(func_addr)[2:]}"
                    
                    current_base_name = re.sub(r'_[0-9a-fA-F]+$', '', func_info['name'])
                    
                    if base_name != current_base_name:
                        print(f"[DEBUG] Attempting to rename function to: {new_name_with_class}")
                        if ida_name.force_name(func_addr, new_name_with_class):
                            print(f"[DEBUG] Successfully renamed function to: {new_name_with_class}")
                            improvements_count += 1
                        else:
                            print(f"[DEBUG] Failed to rename function to: {new_name_with_class}")
                
                # Add function description and analysis as comments
                if suggestions.get("description") or suggestions.get("analysis"):
                    print("[DEBUG] Processing description and analysis")
                    description = suggestions.get("description", "")
                    analysis = suggestions.get("analysis", "")
                    
                    # Format the comment
                    comment = ""
                    if description:
                        if isinstance(description, dict):
                            # Handle structured description
                            desc_parts = []
                            if description.get("summary"):
                                desc_parts.append(f"Summary: {description['summary']}")
                            if description.get("purpose"):
                                desc_parts.append(f"Purpose: {description['purpose']}")
                            if description.get("inputs"):
                                desc_parts.append(f"Inputs: {description['inputs']}")
                            if description.get("outputs"):
                                desc_parts.append(f"Outputs: {description['outputs']}")
                            if description.get("assumptions"):
                                desc_parts.append(f"Assumptions: {description['assumptions']}")
                            comment = "\n".join(desc_parts)
                        else:
                            comment = str(description)
                            
                    if analysis:
                        if comment:
                            comment += "\n\n"
                        if isinstance(analysis, dict):
                            # Handle structured analysis
                            analysis_parts = []
                            for section, content in analysis.items():
                                if isinstance(content, dict):
                                    section_parts = []
                                    for key, value in content.items():
                                        if value:
                                            section_parts.append(f"{key.title()}: {value}")
                                    if section_parts:
                                        analysis_parts.append(f"{section.title()} Analysis:")
                                        analysis_parts.extend(section_parts)
                                else:
                                    if content:
                                        analysis_parts.append(f"{section.title()}: {content}")
                            comment += "\n".join(analysis_parts)
                        else:
                            comment += str(analysis)
                    
                    if comment:
                        print(f"[DEBUG] Calling comment_callback with comment length: {len(comment)}")
                        # Use Gepetto's comment callback
                        comment_callback(func_addr, vu, comment)
                        improvements_count += 1
                
                # Handle variable renaming
                if cfunc and suggestions.get("variables"):
                    print("\n[DEBUG] Processing variable renames")
                    # Convert variables to Gepetto's format
                    var_dict = {}
                    
                    # Process each variable suggestion
                    for var in suggestions["variables"]:
                        old_name = var.get("old_name")
                        new_name = var.get("new_name")
                        
                        if old_name and new_name and old_name != new_name:
                            var_dict[old_name] = new_name
                    
                    if var_dict:
                        print(f"[DEBUG] Calling rename_callback with {len(var_dict)} variables")
                        print(f"[DEBUG] Variable renames: {json.dumps(var_dict, indent=2)}")
                        # Use Gepetto's rename callback
                        rename_callback(func_addr, vu, json.dumps(var_dict), 0)
                        improvements_count += 1
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
                                    improvements_count += 1
                                else:
                                    print(f"[DEBUG] Failed to rename subfunction to: {new_name_with_addr}")
                            else:
                                print(f"[DEBUG] Could not find subfunction address for: {orig_name}")
                
                total_improvements += improvements_count
                return improvements_count
            
            print(f"[DEBUG] Executing UI update for {hex(func_addr)} in main thread")
            # Execute UI updates in main thread with MFF_WRITE flag
            ida_kernwin.execute_sync(update_ui, ida_kernwin.MFF_WRITE)
            
        except Exception as e:
            print(f"[DEBUG] Error applying improvements for {hex(func_addr)}: {str(e)}")
            print(f"[DEBUG] Error traceback: {traceback.format_exc()}")
            
    print(f"\n[DEBUG] Completed apply_improvements. Total improvements: {total_improvements}")
    return total_improvements

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
        
        # Use smaller batch size for better responsiveness
        batch_size = min(5, n)  # Never process more than 5 functions at once for small N
        
        # Create batches of functions
        function_batches = [next_functions[i:i + batch_size] 
                          for i in range(0, len(next_functions), batch_size)]
        
        # Use fewer threads for small batches
        num_threads = min(2, MAX_THREADS) if n <= 10 else MAX_THREADS
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            # Submit function batches for processing
            futures = []
            for batch in function_batches:
                future = executor.submit(process_function_batch, batch, ui, visited, 0)
                futures.append(future)
            
            # Process results as they complete with timeout
            completed = 0
            last_save = 0
            
            for future in as_completed(futures):
                try:
                    # Add 60 second timeout per batch
                    batch_results = future.result(timeout=60)
                    if batch_results:
                        results.extend(batch_results)
                        
                    completed += batch_size
                    progress = (completed * 100) / len(next_functions)
                    status_msg = f"Analyzed {min(completed, len(next_functions))}/{len(next_functions)} functions ({progress:.1f}%)..."
                    print(f"\n{status_msg}")
                    ui.replace_wait_box(status_msg)
                    
                except TimeoutError:
                    print(f"\nWarning: Batch processing timeout - skipping to next batch")
                    continue
                except Exception as e:
                    print(f"\nError processing batch: {str(e)}")
                    continue
                
                # Check for user cancellation more frequently
                if ida_kernwin.user_cancelled():
                    print("\nAnalysis cancelled by user")
                    g_analysis_cancelled = True
                    break
                
                if g_analysis_cancelled:
                    break
                    
        if results:
            # Apply all improvements in the main thread
            print("\nApplying improvements...")
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
        else:
            print("\nNo improvements were made - analysis may have failed")
        
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        traceback.print_exc()
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