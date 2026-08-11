import json
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

LOG_FILE = "logs/attestation.jsonl"
KEYS_DIR = "keys"

def verify_logs():
    print(f"Verifying cryptographic attestations in {LOG_FILE}...\n")
    
    if not os.path.exists(LOG_FILE):
        print("No log file found.")
        return

    valid_count = 0
    with open(LOG_FILE, "r") as f:
        for line_num, line in enumerate(f, 1):
            entry = json.loads(line.strip())
            
            agent = entry.pop("signature")
            agent_name = entry["agent"]
            signature_bytes = bytes.fromhex(agent)
            
            # Reconstruct the exact bytes that were signed
            payload_bytes = json.dumps(entry, sort_keys=True).encode('utf-8')
            
            # Load the agent's public key
            pub_key_path = os.path.join(KEYS_DIR, f"{agent_name}_public.pem")
            try:
                with open(pub_key_path, "rb") as pk_file:
                    public_key = serialization.load_pem_public_key(pk_file.read())
                
                # Cryptographically verify the signature
                public_key.verify(signature_bytes, payload_bytes)
                print(f"✅ Line {line_num}: Valid signature from {agent_name} for '{entry['action']}'")
                valid_count += 1
            except Exception as e:
                print(f"❌ Line {line_num}: INVALID SIGNATURE OR TAMPERED RECORD: {e}")

    print(f"\nVerification complete. {valid_count} cryptographically verified actions.")

if __name__ == "__main__":
    verify_logs()

