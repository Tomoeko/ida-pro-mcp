"""High-level consolidated tools for efficient analysis."""

from __future__ import annotations

import idaapi
import idautils
from typing import Annotated, Literal

from .rpc import tool, get_download_base_url, ext, MCP_SERVER, MCP_EXTENSIONS
import json
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    parse_address,
    normalize_list_input,
    get_function,
    get_prototype,
    get_callees,
    get_callers,
    get_all_xrefs,
    extract_function_strings,
    extract_function_constants,
    decompile_function_safe,
    get_assembly_lines,
)
from .api_composite import (
    _resolve_addr,
    _analyze_function_internal,
    _compact_strings,
    _basic_block_info,
)

@tool
@idasync
@tool_timeout(180.0)
def analyze_functions_batch(
    addrs: Annotated[list[str] | str, "List of function addresses or names"],
    detail_level: Annotated[Literal["minimal", "standard"], "Detail level for each function"] = "standard",
) -> list[dict]:
    """Analyze multiple functions in a single call.
    'minimal': Returns name, address, size, and basic block count.
    'standard': Returns the same as analyze_function but in a batch.
    Use this to triage a module or a set of xrefs efficiently."""
    
    raw = normalize_list_input(addrs)
    results = []
    
    for addr_str in raw:
        try:
            ea = _resolve_addr(addr_str)
            if detail_level == "minimal":
                func = idaapi.get_func(ea)
                if not func:
                    results.append({"addr": addr_str, "error": "No function"})
                    continue
                bb = _basic_block_info(ea)
                results.append({
                    "addr": hex(ea),
                    "name": idaapi.get_func_name(ea) or "",
                    "size": func.end_ea - func.start_ea,
                    "basic_blocks": bb["count"],
                    "complexity": bb["cyclomatic_complexity"]
                })
            else:
                results.append(_analyze_function_internal(ea))
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})
            
    return results

@tool
@idasync
@tool_timeout(180.0)
def analyze_recursive(
    addr: Annotated[str, "Root function address or name"],
    depth: Annotated[int, "Recursion depth for neighbors (default 1)"] = 1,
    include_callees: Annotated[bool, "Include callees in recursion"] = True,
    include_callers: Annotated[bool, "Include callers in recursion"] = True,
) -> dict:
    """Analyze a function and its immediate neighbors (callers/callees) in one go.
    Root function gets standard analysis (decompilation, strings, etc.).
    Neighbors get minimal analysis to save tokens.
    Ideal for understanding function context without manual chaining."""
    
    try:
        root_ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}
    
    root_analysis = _analyze_function_internal(root_ea)
    
    # Track all uniquely identified neighbors
    neighbors = {}
    
    def _add_neighbor(ea: int):
        if ea == root_ea or ea in neighbors:
            return
        func = idaapi.get_func(ea)
        if not func:
            return
        bb = _basic_block_info(ea)
        neighbors[ea] = {
            "addr": hex(ea),
            "name": idaapi.get_func_name(ea) or "",
            "size": func.end_ea - func.start_ea,
            "basic_blocks": bb["count"]
        }

    # Depth 1: Immediate neighbors
    if depth >= 1:
        if include_callees:
            callees = get_callees(hex(root_ea))
            for c in callees:
                try:
                    c_ea = _resolve_addr(c["addr"])
                    _add_neighbor(c_ea)
                except: continue
        
        if include_callers:
            callers = get_callers(hex(root_ea))
            for c in callers:
                try:
                    c_ea = _resolve_addr(c["addr"])
                    _add_neighbor(c_ea)
                except: continue

    root_analysis["neighbors"] = list(neighbors.values())
    return root_analysis

@tool
def search_and_triage(pattern: str, search_type: str = "string", max_results: int = 20) -> list[dict]:
    """Search for string or byte patterns and return immediate surrounding context.
    
    This consolidates searching and initial triage. Instead of just returning addresses,
    it returns the data/function containing the result to save a follow-up call.
    
    Args:
        pattern: The string or byte pattern to search for.
        search_type: 'string' or 'bytes'
        max_results: Max hits to process and return.
    """
    import ida_bytes
    import ida_search
    import ida_nalt
    import idc
    
    results = []
    addr = ida_nalt.get_imagebase()
    end = ida_nalt.get_max_ea()
    
    flag = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
    
    count = 0
    while addr < end and count < max_results:
        if search_type == "string":
            addr = ida_search.find_text(addr, 0, 0, pattern, flag)
        else:
            addr = ida_search.find_binary(addr, end, pattern, 16, flag)
            
        if addr == idc.BADADDR:
            break
            
        # Get context
        flags = ida_bytes.get_flags(addr)
        ctx = {"addr": hex(addr)}
        if ida_bytes.is_code(flags):
            ctx["type"] = "code"
            ctx["name"] = idc.get_func_name(addr) or idc.get_name(addr)
        elif ida_bytes.is_data(flags):
            ctx["type"] = "data"
            ctx["name"] = idc.get_name(addr)
            if ida_bytes.is_strlit(flags):
                ctx["string"] = idc.get_strlit_contents(addr)
        
        results.append(ctx)
        addr = ida_bytes.next_head(addr, end)
        count += 1
        
    return results

@tool
def ida_extension_manager(action: str, extension_group: str | None = None, tool_name: str | None = None, tool_args: dict | None = None) -> dict:
    """Dynamically discover and execute specialized extension tools that are not in the core API.
    
    Use this to access the advanced tools that were hidden to optimize context token usage.
    
    Args:
        action: "list_groups", "list_tools", or "execute".
        extension_group: Target group (e.g., 'adv', 'mod', 'stk', 'exp') required for list_tools.
        tool_name: Name of the specialized tool to execute (required for 'execute').
        tool_args: Dictionary of arguments for the tool (required for 'execute').
        
    Returns:
        JSON response with available groups, tool schemas, or the execution result.
    """
    if action == "list_groups":
        return {
            "groups": list(MCP_EXTENSIONS.keys()),
            "description": "Pass a group name to 'action: list_tools' to see available tools and their schemas."
        }
        
    elif action == "list_all":
        summary = {}
        for grp, tools in MCP_EXTENSIONS.items():
            summary[grp] = {}
            for t_name in tools:
                func = MCP_SERVER.tools.methods.get(t_name)
                if func:
                    doc = (func.__doc__ or "").strip().split("\n")[0]
                    summary[grp][t_name] = doc
        return summary
        
    elif action == "list_tools":
        if not extension_group or extension_group not in MCP_EXTENSIONS:
            return {"error": f"Invalid or missing extension_group. Available: {list(MCP_EXTENSIONS.keys())}"}
        
        tools_info = []
        for name in MCP_EXTENSIONS[extension_group]:
            func = MCP_SERVER.tools.methods.get(name)
            if func:
                tools_info.append(MCP_SERVER._generate_tool_schema(name, func))
        return {"extension_group": extension_group, "tools": tools_info}
        
    elif action == "execute":
        if not tool_name:
            return {"error": "tool_name is required for execute action."}
            
        func = MCP_SERVER.tools.methods.get(tool_name)
        if not func:
            return {"error": f"Tool '{tool_name}' not found."}
            
        # Bypass the extension check constraints in MCP_SERVER and execute directly
        try:
            kwargs = tool_args or {}
            # We call the python function directly rather than through dict dispatch 
            # to bypass MCP_SERVER's _mcp_tools_call extension check
            result = func(**kwargs)
            return {"result": result}
        except TypeError as e:
            schema_hint = MCP_SERVER._generate_tool_schema(tool_name, func)
            return {
                "error": f"Argument error: {str(e)}", 
                "schema_hint": schema_hint.get("inputSchema", {})
            }
        except Exception as e:
            import traceback
            return {"error": str(e), "traceback": traceback.format_exc()}
            
    else:
        return {"error": f"Unknown action '{action}'"}
