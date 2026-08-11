import functools
from attestation import log_signed_action

AGENT_CAPABILITIES = {
    "analysis_agent": {"read_repo_list", "read_metadata"},
    "code_review_agent": {"read_file", "flag_violation"},
    "developer_agent": {"read_file", "write_patch"},
    "commit_agent": {"create_branch", "merge_to_main"},
}

def enforce_capability(action_name):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            agent_name = kwargs.get("agent_name", "unknown")
            
            allowed_actions = AGENT_CAPABILITIES.get(agent_name, set())
            
            if action_name not in allowed_actions:
                print(f"\n[SECURITY ALERT] 🚨 Blocked '{agent_name}' from executing unauthorized action: '{action_name}'")
                raise PermissionError(
                    f"Agent '{agent_name}' lacks capability '{action_name}'. "
                    f"Allowed capabilities: {allowed_actions}"
                )
            
            # --- NEW ATTESTATION CODE ---
            # Extract a "target" string for the log (e.g., the file being read or the repo being pushed to)
            target = "unknown_target"
            if len(args) > 0:
                target = str(args[0])
            elif "repo_name" in kwargs:
                target = kwargs["repo_name"]
            elif "file_url" in kwargs:
                target = kwargs["file_url"]
                
            # Cryptographically sign the intent BEFORE execution
            log_signed_action(agent_name, action_name, target)
            # ----------------------------

            return func(*args, **kwargs)
        return wrapper
    return decorator

