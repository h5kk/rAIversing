import idaapi
import idautils
import idc
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from rich.console import Console
from collections import defaultdict

from .ai_interface import AIInterface
from .utils import get_function_context, sanitize_name, get_function_layer, get_function_complexity

class ReversingEngine:
    def __init__(self, ai_module: AIInterface, max_tokens: Optional[int] = None, batch_size: int = 5):
        self.ai_module = ai_module
        self.max_tokens = max_tokens or ai_module.get_max_tokens()
        self.batch_size = batch_size
        self.console = Console()
        self.logger = logging.getLogger("ReversingEngine")
        self.processed_functions: Set[int] = set()
        self.function_cache: Dict[int, dict] = {}
        
        # Initialize IDA API
        if not idaapi.get_plugin_options("AUTOSCRIPT"):
            self.logger.error("This script must be run from within IDA Pro")
            raise RuntimeError("Script must be run from within IDA Pro")
    
    def get_all_functions(self) -> List[int]:
        """Get all function addresses in the binary."""
        return list(idautils.Functions())
    
    def get_function_info(self, func_addr: int) -> dict:
        """Get detailed information about a function."""
        if func_addr in self.function_cache:
            return self.function_cache[func_addr]
            
        func = idaapi.get_func(func_addr)
        if not func:
            raise ValueError(f"No function at address {hex(func_addr)}")
            
        # Get decompiled code
        cfunc = idaapi.decompile(func)
        if not cfunc:
            raise ValueError(f"Could not decompile function at {hex(func_addr)}")
            
        # Get function context
        context = get_function_context(func)
        
        info = {
            "address": func_addr,
            "name": idc.get_func_name(func_addr),
            "code": str(cfunc),
            "context": context,
            "calls": list(idautils.CodeRefsFrom(func_addr, True)),
            "called_by": list(idautils.CodeRefsTo(func_addr, True)),
            "improved": False,
            "layer": get_function_layer(func_addr),
            "complexity": get_function_complexity(func_addr)
        }
        
        self.function_cache[func_addr] = info
        return info
    
    def group_related_functions(self, functions: List[int]) -> List[List[int]]:
        """Group functions that are likely related for batch analysis."""
        groups = []
        current_group = []
        
        # Sort functions by layer and complexity
        sorted_funcs = sorted(
            functions,
            key=lambda f: (
                self.get_function_info(f)["layer"],
                self.get_function_info(f)["complexity"]
            )
        )
        
        # Group functions by call relationships and complexity
        call_graph = defaultdict(set)
        for func_addr in sorted_funcs:
            info = self.get_function_info(func_addr)
            for call in info["calls"]:
                call_graph[func_addr].add(call)
                
        # Create groups of related functions
        used = set()
        for func_addr in sorted_funcs:
            if func_addr in used:
                continue
                
            current_group = [func_addr]
            used.add(func_addr)
            
            # Add related functions
            related = set()
            related.update(call_graph[func_addr])  # Functions it calls
            for f in sorted_funcs:  # Functions that call it
                if func_addr in call_graph[f]:
                    related.add(f)
                    
            # Add most relevant related functions
            for rel_func in sorted(related, key=lambda f: get_function_complexity(f)):
                if len(current_group) >= self.batch_size:
                    break
                if rel_func not in used:
                    current_group.append(rel_func)
                    used.add(rel_func)
                    
            groups.append(current_group)
            
        return groups
    
    def improve_function_batch(self, func_addrs: List[int]) -> bool:
        """Improve a batch of related functions using AI."""
        try:
            # Prepare function batch
            functions = []
            for addr in func_addrs:
                if addr in self.processed_functions:
                    continue
                    
                func_info = self.get_function_info(addr)
                functions.append({
                    "code": func_info["code"],
                    "context": func_info["context"]
                })
                
            if not functions:
                return True
                
            # Get AI suggestions for the batch
            suggestions = self.ai_module.analyze_functions(functions)
            
            # Apply suggestions
            for i, (addr, suggestion) in enumerate(zip(func_addrs, suggestions)):
                if not suggestion:
                    continue
                    
                func_info = self.get_function_info(addr)
                
                # Apply new names
                if "renames" in suggestion:
                    for old_name, new_name in suggestion["renames"].items():
                        sanitized_name = sanitize_name(new_name)
                        if old_name == func_info["name"]:
                            idc.set_name(addr, sanitized_name)
                        else:
                            # Handle parameter and variable renaming
                            # TODO: Implement variable renaming
                            pass
                            
                # Store additional analysis
                func_info["category"] = suggestion.get("category", "unknown")
                func_info["security_relevant"] = suggestion.get("security_relevant", False)
                func_info["relationships"] = suggestion.get("relationships", [])
                func_info["shared_purpose"] = suggestion.get("shared_purpose")
                func_info["improved"] = True
                
                self.processed_functions.add(addr)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error improving function batch: {str(e)}")
            return False
    
    def improve_all_functions(self) -> None:
        """Improve all functions in the binary using batch processing."""
        functions = self.get_all_functions()
        total = len(functions)
        
        self.console.print(f"[bold green]Found {total} functions to process[/bold green]")
        
        # Group related functions
        groups = self.group_related_functions(functions)
        
        self.console.print(f"[bold blue]Grouped into {len(groups)} batches[/bold blue]")
        
        # Process each group
        for i, group in enumerate(groups, 1):
            self.console.print(
                f"[bold blue]Processing batch {i}/{len(groups)} "
                f"({len(group)} functions)[/bold blue]"
            )
            self.improve_function_batch(group)
            
        self.console.print("[bold green]Completed processing all functions[/bold green]")
    
    def save_state(self, path: str) -> None:
        """Save the current state to a file."""
        state = {
            "processed_functions": list(self.processed_functions),
            "function_cache": self.function_cache
        }
        
        Path(path).write_text(json.dumps(state, indent=4))
    
    def load_state(self, path: str) -> None:
        """Load state from a file."""
        if not Path(path).exists():
            return
            
        state = json.loads(Path(path).read_text())
        self.processed_functions = set(state["processed_functions"])
        self.function_cache = state["function_cache"] 