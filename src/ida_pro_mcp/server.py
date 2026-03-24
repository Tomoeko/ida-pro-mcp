import argparse
import http.client
import json
import os
import sys
import traceback
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import list_available_clients, print_mcp_config, run_install_command, set_ida_rpc
except ImportError:
    from installer import list_available_clients, print_mcp_config, run_install_command, set_ida_rpc

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

def get_active_ports() -> list[int]:
    """Scan 13337-13346 for active IDA instances."""
    active = []
    for p in range(13337, 13347):
        try:
            conn = http.client.HTTPConnection(IDA_HOST, p, timeout=0.1)
            # Use a fast health check
            req = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "server_health", "arguments": {}}, "id": 1}
            conn.request("POST", "/mcp", json.dumps(req).encode("utf-8"), {"Content-Type": "application/json"})
            resp = conn.getresponse()
            if resp.status == 200:
                active.append(p)
            conn.close()
        except Exception:
            pass
    return active


def _optimize_content(content_arr: list[dict]) -> list[dict]:
    """Minify JSON strings and truncate extremely large text blocks."""
    MAX_TEXT_SIZE = 64 * 1024  # 64KB per block
    
    optimized = []
    for c in content_arr:
        if c.get("type") == "text":
            t = c.get("text", "")
            if t.strip().startswith(("{", "[")):
                try:
                    # Minify JSON
                    t = json.dumps(json.loads(t), separators=(',', ':'))
                except Exception:
                    pass
            
            if len(t) > MAX_TEXT_SIZE:
                t = t[:MAX_TEXT_SIZE] + "\n... (truncated due to size) ..."
            
            optimized.append({"type": "text", "text": t})
        else:
            optimized.append(c)
    return optimized


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry."""
    global IDA_PORT
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    if request_obj["method"] == "initialize":
        return dispatch_original(request)
    if request_obj["method"].startswith("notifications/"):
        return dispatch_original(request)

    target_ports = [IDA_PORT]
    is_multi = False

    try:
        if request_obj["method"] == "tools/call":
            tool_name = request_obj["params"].get("name")
            if tool_name == "switch_ida_instance":
                port = int(request_obj["params"].get("arguments", {}).get("port", 13337))
                IDA_PORT = port
                return JsonRpcResponse({
                    "jsonrpc": "2.0",
                    "result": {"content": [{"type": "text", "text": f"Switched active IDA instance to port {port}"}], "isError": False},
                    "id": request_obj.get("id")
                })
            elif tool_name == "list_ida_instances":
                active_ports = get_active_ports()
                if not active_ports:
                    content = "No active IDA instances found between ports 13337 and 13346."
                else:
                    content = "Active IDA instances:\n"
                    for p in active_ports:
                        content += f"- Port {p}: Online\n"
                
                return JsonRpcResponse({
                    "jsonrpc": "2.0",
                    "result": {"content": [{"type": "text", "text": content}], "isError": False},
                    "id": request_obj.get("id")
                })

            args = request_obj["params"].get("arguments", {})
            
            # Discovery tools default to 'all' if no port/ports specified
            DISCOVERY_TOOLS = ["survey_binary", "server_health"]
            if tool_name in DISCOVERY_TOOLS and "port" not in args and "ports" not in args:
                args["ports"] = "all"

            if "ports" in args:
                ports_arg = args.pop("ports")
                if ports_arg == "all" or ports_arg == ["all"]:
                    target_ports = get_active_ports()
                    is_multi = True
                elif isinstance(ports_arg, list) and ports_arg:
                    target_ports = []
                    for p in ports_arg:
                        try:
                            target_ports.append(int(p))
                        except ValueError:
                            pass
                    is_multi = bool(target_ports)
            elif "port" in args:
                port_arg = args.pop("port")
                if port_arg:
                    target_ports = [int(port_arg)]
                    is_multi = True
            
            # Pop optional executable_name so it doesn't break underlying API functions
            args.pop("executable_name", None)

            request_obj["params"]["arguments"] = args

        payload = json.dumps(request_obj).encode("utf-8")
        if is_multi and request_obj["method"] == "tools/call":
            combined_content = []
            has_error = False
            for p in target_ports:
                try:
                    conn = http.client.HTTPConnection(IDA_HOST, p, timeout=30)
                    conn.request("POST", "/mcp", payload, {"Content-Type": "application/json"})
                    response = conn.getresponse()
                    raw_data = response.read().decode()
                    if response.status >= 400:
                        header = f"--- Port {p} ---\n" if len(target_ports) > 1 else ""
                        combined_content.append({"type": "text", "text": f"{header}HTTP {response.status} {response.reason}: {raw_data}\n\n"})
                        has_error = True
                        continue
                        
                    resp_obj = json.loads(raw_data)
                    header = f"--- Port {p} ---\n" if len(target_ports) > 1 else ""

                    if "error" in resp_obj:
                        err_msg = resp_obj["error"].get("message", str(resp_obj["error"]))
                        combined_content.append({"type": "text", "text": f"{header}Error: {err_msg}\n\n"})
                        has_error = True
                    elif "result" in resp_obj:
                        content_arr = resp_obj["result"].get("content", [])
                        optimized = _optimize_content(content_arr)
                        
                        if optimized:
                            # Prepend header to first text block if multi
                            if header and optimized[0]["type"] == "text":
                                optimized[0]["text"] = header + optimized[0]["text"]
                            combined_content.extend(optimized)
                        
                        if resp_obj["result"].get("isError"):
                            has_error = True
                except Exception as e:
                    header = f"--- Port {p} ---\n" if len(target_ports) > 1 else ""
                    combined_content.append({"type": "text", "text": f"{header}Request failed: {str(e)}\n\n"})
                    has_error = True
                finally:
                    if 'conn' in locals() and hasattr(conn, "close"):
                        conn.close()
                        
            return JsonRpcResponse({
                "jsonrpc": "2.0",
                "result": {"content": combined_content, "isError": has_error},
                "id": request_obj.get("id")
            })

        conn = http.client.HTTPConnection(IDA_HOST, target_ports[0], timeout=30)
        try:
            conn.request(
                "POST",
                "/mcp",
                payload,
                {"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            raw_data = response.read().decode()
            if response.status >= 400:
                raise RuntimeError(
                    f"HTTP {response.status} {response.reason}: {raw_data}"
                )
            resp_obj = json.loads(raw_data)
            
            # Apply optimization to single-port results
            if "result" in resp_obj and "content" in resp_obj["result"]:
                resp_obj["result"]["content"] = _optimize_content(resp_obj["result"]["content"])
            
            # Inject custom multiplexer tools into tools/list response
            if request_obj["method"] == "tools/list" and "result" in resp_obj and "tools" in resp_obj["result"]:
                for t in resp_obj["result"]["tools"]:
                    if "inputSchema" in t and "properties" in t["inputSchema"]:
                        t["inputSchema"]["properties"]["ports"] = {
                            "oneOf": [
                                {"type": "array", "items": {"type": "integer"}},
                                {"type": "string", "enum": ["all"]}
                            ],
                            "description": "Optional: Array of ports or 'all' to broadcast this tool call to multiple instances at once."
                        }
                        t["inputSchema"]["properties"]["port"] = {
                            "type": "integer",
                            "description": "Optional: Execute this tool on a specific IDA instance port."
                        }
                        t["inputSchema"]["properties"]["executable_name"] = {
                            "type": "string",
                            "description": "Optional: Provide the executable name for context clarification."
                        }
                resp_obj["result"]["tools"].extend([
                    {
                        "name": "switch_ida_instance",
                        "description": "Switches the active IDA instance to the specified port.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"port": {"type": "integer", "description": "The port number of the IDA instance (e.g. 13337 to 13346)"}},
                            "required": ["port"]
                        }
                    },
                    {
                        "name": "list_ida_instances",
                        "description": "Pings ports 13337-13346 to find active IDA instances and returns their status.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }
                    }
                ])
            return resp_obj
        finally:
            conn.close()
    except Exception as e:
        full_info = traceback.format_exc()
        request_id = request_obj.get("id")
        if request_id is None:
            return None  # Notification, no response needed

        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "Failed to complete request to IDA Pro. "
                        f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
                        "The request was not retried automatically. "
                        "If this was a mutating operation, verify IDA state before retrying.\n"
                        f"{full_info}"
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )


mcp.registry.dispatch = dispatch_proxy


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: 'project' (current directory, default) or 'global' (user-level)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=f"http://{IDA_HOST}:{IDA_PORT}",
        help=f"IDA RPC server to use (default: http://{IDA_HOST}:{IDA_PORT})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    args = parser.parse_args()

    # Handle --list-clients independently
    if args.list_clients:
        list_available_clients()
        return

    # Parse IDA RPC server argument
    ida_rpc = urlparse(args.ida_rpc)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
    IDA_HOST = ida_rpc.hostname
    IDA_PORT = ida_rpc.port
    set_ida_rpc(IDA_HOST, IDA_PORT)

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        print_mcp_config()
        return

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
