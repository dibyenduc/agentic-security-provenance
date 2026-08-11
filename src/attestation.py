import os
import json
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

LOG_FILE = "logs/attestation.jsonl"
KEYS_DIR = "keys"

# Ensure directories exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# Cache keys in memory so we don't regenerate them on every action
_key_cache = {}

def get_or_create_keypair(agent_name: str):
    """Retrieve an existing Ed25519 keypair for an agent, or generate a new one."""
    if agent_name in _key_cache:
        return _key_cache[agent_name]

    priv_key_path = os.path.join(KEYS_DIR, f"{agent_name}_private.pem")
    pub_key_path = os.path.join(KEYS_DIR, f"{agent_name}_public.pem")

    if os.path.exists(priv_key_path):
        # Load existing key
        with open(priv_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        # Generate new key
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        # Save private key
        with open(priv_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key (for verification later)
        public_key = private_key.public_key()
        with open(pub_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    _key_cache[agent_name] = private_key
    return private_key

def log_signed_action(agent_name: str, action: str, target: str):
    """Sign an action cryptographically and append it to the tamper-evident log."""
    private_key = get_or_create_keypair(agent_name)
    
    # Create the payload we want to attest to
    payload = {
        "agent": agent_name,
        "action": action,
        "target": target,
        "timestamp": time.time()
    }
    
    # Convert to bytes for signing
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    
    # Generate Ed25519 signature (returns raw bytes)
    signature = private_key.sign(payload_bytes)
    
    # Add the hex signature to our log entry
    payload["signature"] = signature.hex()
    
    # Append to log
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(payload) + "\n")
    
    print(f"[ATTESTATION] 🔐 {agent_name} cryptographically signed action '{action}' on '{target}'")

