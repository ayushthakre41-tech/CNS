import argparse
import sys
import os
import requests
import json

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from client.encryption import E2EEncryption

def main():
    parser = argparse.ArgumentParser(description="E2EE Auditor - Command Line Receiver Client")
    parser.add_argument("--receiver", "-r", type=str, default="Bob", help="Receiver identifier")
    parser.add_argument("--password", "-p", type=str, default="securepassword123", help="Shared secret passphrase")
    parser.add_argument("--server", type=str, default="http://127.0.0.1:5000", help="Relay server URL")

    args = parser.parse_args()

    recv_url = f"{args.server.rstrip('/')}/receive?receiver={args.receiver}"
    print(f"\n[Receiver] Polling relay server for recipient '{args.receiver}': {recv_url}")

    try:
        resp = requests.get(recv_url, timeout=5)
        if resp.status_code != 200:
            print(f"[Receiver ERROR] Server returned HTTP {resp.status_code}: {resp.text}")
            return

        data = resp.json()
        messages = data.get("messages", [])
        print(f"[Receiver] Received {len(messages)} message(s) from server queue.\n")

        for idx, msg in enumerate(messages, 1):
            print(f"--- Message {idx} (ID: {msg.get('id')}) ---")
            print(f"From: {msg.get('sender')}")
            print(f"Timestamp: {msg.get('timestamp')}")
            
            payload = msg.get("payload")
            is_encrypted = msg.get("is_encrypted", True)

            if is_encrypted and isinstance(payload, dict):
                print(f"[Receiver] Payload is Encrypted (AES-256-GCM). Attempting decryption...")
                try:
                    plaintext, dec_time_ms = E2EEncryption.decrypt(payload, args.password)
                    print(f"[Receiver SUCCESS] Decrypted Plaintext: '{plaintext}'")
                    print(f"[Receiver SUCCESS] Decryption time: {dec_time_ms} ms | Auth Tag Validated!")
                except Exception as err:
                    print(f"[Receiver FAILED] Decryption failed: {str(err)}")
            else:
                print(f"[Receiver UNENCRYPTED] Plaintext payload: '{payload}'")
            print("-" * 40)

    except Exception as e:
        print(f"[Receiver FAILURE] Could not connect to relay server: {str(e)}")

if __name__ == "__main__":
    main()
