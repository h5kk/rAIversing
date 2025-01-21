import re
import idaapi
import idautils
import idc
from typing import Dict, List, Set

def sanitize_name(name: str) -> str:
    """Sanitize a name to be valid in IDA."""
    # Remove invalid characters
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    
    # Ensure it starts with a letter or underscore
    if name[0].isdigit():
        name = '_' + name
        
    return name
    
def get_function_context(func: idaapi.func_t) -> Dict:
    """Get context information about a function."""
    context = {
        "called_by": [],
        "calls": [],
        "data_refs": [],
        "strings": [],
        "constants": set(),
        "struct_refs": []
    }
    
    # Get function boundaries
    start_ea = func.start_ea
    end_ea = func.end_ea
    
    # Get cross-references to this function
    for ref in idautils.CodeRefsTo(start_ea, True):
        caller_name = idc.get_func_name(ref)
        if caller_name:
            context["called_by"].append(caller_name)
            
    # Get functions called by this function
    for head in idautils.Heads(start_ea, end_ea):
        # Get code references
        for ref in idautils.CodeRefsFrom(head, True):
            called_name = idc.get_func_name(ref)
            if called_name and called_name != idc.get_func_name(start_ea):
                context["calls"].append(called_name)
                
        # Get data references
        for ref in idautils.DataRefsFrom(head):
            # Check if it's a string
            string = idc.get_strlit_contents(ref)
            if string:
                context["strings"].append(string.decode('utf-8', errors='ignore'))
                continue
                
            # Check if it's a constant
            value = idc.get_wide_dword(ref)
            if value:
                context["constants"].add(value)
                
            # Check if it's a structure reference
            struc = get_struct_from_ref(ref)
            if struc:
                context["struct_refs"].append(struc)
                
    # Remove duplicates and sort
    context["called_by"] = sorted(set(context["called_by"]))
    context["calls"] = sorted(set(context["calls"]))
    context["strings"] = sorted(set(context["strings"]))
    context["constants"] = sorted(context["constants"])
    context["struct_refs"] = sorted(set(context["struct_refs"]))
    
    return context
    
def get_struct_from_ref(ea: int) -> str:
    """Get structure name from a reference address."""
    try:
        ti = idaapi.tinfo_t()
        if idaapi.get_tinfo(ti, ea):
            if ti.is_struct():
                return str(ti.get_type_name())
    except:
        pass
    return None
    
def get_function_layer(func_addr: int) -> int:
    """Calculate the layer of a function based on its call depth."""
    seen = set()
    
    def get_depth(addr: int) -> int:
        if addr in seen:
            return 0
        seen.add(addr)
        
        max_depth = 0
        func = idaapi.get_func(addr)
        if not func:
            return 0
            
        # Get all function calls
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for ref in idautils.CodeRefsFrom(head, True):
                if idaapi.get_func(ref):
                    max_depth = max(max_depth, get_depth(ref) + 1)
                    
        return max_depth
        
    return get_depth(func_addr)
    
def get_function_complexity(func_addr: int) -> float:
    """Calculate function complexity score."""
    func = idaapi.get_func(func_addr)
    if not func:
        return 0.0
        
    # Basic metrics
    num_instructions = 0
    num_basic_blocks = 0
    num_edges = 0
    num_calls = 0
    
    # Count basic blocks and edges
    f = idaapi.FlowChart(func)
    num_basic_blocks = f.size()
    for block in f:
        num_edges += len(list(block.succs()))
        
    # Count instructions and calls
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            num_instructions += 1
            if idaapi.is_call_insn(head):
                num_calls += 1
                
    # Calculate cyclomatic complexity
    cyclomatic = num_edges - num_basic_blocks + 2
    
    # Combine metrics into a single score
    # Higher score = more complex
    score = (
        (num_instructions * 0.1) +
        (num_basic_blocks * 0.3) +
        (cyclomatic * 0.4) +
        (num_calls * 0.2)
    )
    
    return score 