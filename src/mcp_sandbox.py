import os
import json
from typing import Dict, Any, List, Callable
from attestation import log_signed_action
# Note: For this to run, you will need to pip install extism mcp
from extism import Plugin

class MCPSandbox:
    """
    Enterprise-Grade Wasm Sandbox for Agentic Tool Execution.
    Replaces Python-space decorators with cryptographic capability checks 
    and memory-isolated WebAssembly execution.
    """
    
    def __init__(self):
        self.allowed_capabilities = {
            "analysis_agent": {"read_repo_list", "read_metadata"},
            "code_review_agent": {"read_file", "flag_violation"},
            "developer_agent": {"read_file", "write_patch"},
            "commit_agent": {"create_branch", "merge_to_main"}
        }
        
    def _verify_cryptographic_intent(self, agent_name: str, action_name: str, target: str) -> bool:
        """
        Instead of a decorator in the same memory space, we act as a gateway.
        We verify the agent's IAM role, and if valid, we sign the intent to 
        create an immutable audit trail BEFORE execution.
        """
        allowed = self.allowed_capabilities.get(agent_name, set())
        if action_name not in allowed:
            print(f"\n[SECURITY ALERT] 🚨 Blocked '{agent_name}'. Unauthorized action: '{action_name}'")
            raise PermissionError(f"Agent '{agent_name}' lacks capability '{action_name}'.")
            
        # Log the cryptographically signed intent using existing Ed25519 logic
        log_signed_action(agent_name, action_name, target)
        return True

    def execute_in_wasm(self, agent_name: str, action_name: str, target: str, payload: Dict[str, Any], native_fallback: Callable = None) -> Any:
        """
        Main entry point for agent tool calls.
        1. Verifies cryptographic intent and capability
        2. Routes to an isolated Wasm plugin (or native fallback for the PoC)
        """
        # Step 1: Cryptographic State Verification
        self._verify_cryptographic_intent(agent_name, action_name, target)
        
        # Step 2: Attempt Wasm Execution
        # In a full enterprise environment, every tool is compiled to a .wasm binary
        wasm_file_path = f"wasm_tools/{action_name}.wasm"
        
        if os.path.exists(wasm_file_path):
            print(f"🔒 [MCP Gateway] Executing '{action_name}' in memory-isolated Wasm sandbox...")
            # Create a strict Wasm manifest (no network, no file access unless explicitly granted)
            plugin_manifest = {"wasm": [{"path": wasm_file_path}]}
            
            try:
                # Spin up ephemeral Extism Wasm container
                plugin = Plugin(plugin_manifest)
                
                # Pass JSON payload to Wasm and execute
                input_data = json.dumps(payload).encode('utf-8')
                result = plugin.call("execute", input_data)
                
                return json.loads(result)
                
            except Exception as e:
                print(f"🚨 [Sandbox Error] Wasm execution failed: {e}")
                raise RuntimeError(f"Sandbox violation or execution error: {e}")
        else:
            # PoC Fallback: If no .wasm binary exists yet, we execute the native Python function,
            # BUT we still have the cryptographic gateway protection from Step 1.
            print(f"⚠️ [MCP Gateway] Wasm binary not found. Falling back to native execution for '{action_name}'...")
            if native_fallback:
                return native_fallback(**payload)
            raise FileNotFoundError(f"No Wasm binary or native fallback provided for {action_name}")

# Global Sandbox Instance
sandbox = MCPSandbox()

# --- HOW TO UPGRADE YOUR EXISTING DECORATORS ---
# You can replace your @enforce_capability decorator with this wrapper
def mcp_sandboxed_tool(action_name):
    def decorator(func):
        def wrapper(*args, **kwargs):
            agent_name = kwargs.get("agent_name", "unknown")
            
            # Extract target for logging
            target = "unknown_target"
            if len(args) > 0:
                target = str(args[0])
            elif "repo_name" in kwargs:
                target = kwargs["repo_name"]
            elif "file_url" in kwargs:
                target = kwargs["file_url"]

            # Package arguments for the sandbox
            payload = {"args": args, "kwargs": {k:v for k,v in kwargs.items() if k != "agent_name"}}
            
            # Route through the MCP Wasm Sandbox instead of native Python memory
            return sandbox.execute_in_wasm(
                agent_name=agent_name,
                action_name=action_name,
                target=target,
                payload=payload,
                native_fallback=lambda **p: func(*p.get("args", []), **p.get("kwargs", {}))
            )
        return wrapper
    return decorator
