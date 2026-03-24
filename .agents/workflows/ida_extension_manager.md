---
description: How to access advanced IDA Pro tools using the ida_extension_manager
---
# Advanced IDA Pro Tools via Extension Manager

The `ida-pro-mcp` handles core operations natively, but to keep the core token footprint low, many specialized and advanced IDA Pro tools were moved into hidden Extension Groups (e.g., `adv`, `dbg`, `exp`, `mod`).

**IMPORTANT for AI Agents:** When you cannot find a specific reverse engineering tool in your base schema (e.g., raw byte scanning, querying entity SQL databases, callgraphs, raw disassembly), you SHOULD use the `mcp_ida-pro-mcp_ida_extension_manager` tool to dynamically discover and execute it!

## Step-by-Step Discovery and Execution:

1. **List the Available Groups**:
   Use `mcp_ida-pro-mcp_ida_extension_manager` with `action: "list_groups"` to see what extension groups are available.
   
2. **List the Hidden Tools**:
   Use `mcp_ida-pro-mcp_ida_extension_manager` with `action: "list_tools"` and an `extension_group` (like `"adv"`) to return the massive JSON schema of all tools housed in that group.
   *Example:* Inside `adv`, you will find highly capable tools like `find_bytes`, `disasm`, `callgraph`, `entity_query`, `func_profile`, and more!
   
3. **Execute the Hidden Tool**:
   Use `mcp_ida-pro-mcp_ida_extension_manager` with `action: "execute"`. Provide the `tool_name` (e.g., `"find_bytes"`) and the `tool_args` as a dictionary (e.g., `{"patterns": "48 83 ec ??"}`). Add `port` to target specific multiplexed instances.

*Tip: Treat the extension manager as your escape hatch when complex triage is needed but the core commands fall short.*
