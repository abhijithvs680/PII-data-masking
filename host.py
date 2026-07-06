import os
import sys
import time
import subprocess
from pyngrok import ngrok, conf

def update_env(backend_url):
    print(f"[*] Updating frontend/.env with VITE_API_URL={backend_url}")
    with open("frontend/.env", "w") as f:
        f.write(f"VITE_API_URL={backend_url}\n")
        
    print(f"[*] Updating docker-compose.yml with VITE_API_URL={backend_url}")
    with open("docker-compose.yml", "r") as f:
        content = f.read()
        
    import re
    # Replace VITE_API_URL=... with the new backend URL
    new_content = re.sub(r'VITE_API_URL=.*', f'VITE_API_URL={backend_url}', content)
    
    with open("docker-compose.yml", "w") as f:
        f.write(new_content)

def main():
    try:
        print("[*] Starting ngrok tunnel for backend (Port 5002)...")
        backend_tunnel = ngrok.connect(5002, bind_tls=True)
        backend_url = backend_tunnel.public_url
        print(f"[+] Backend Tunnel established at: {backend_url}")
        
        # 1. Update config files with the new dynamic backend URL
        update_env(backend_url)
        
        # 2. Restart Docker containers so the frontend rebuilds with the new VITE_API_URL
        print("[*] Rebuilding and restarting Docker containers...")
        subprocess.run(["docker-compose", "up", "--build", "-d"], check=True)
        
        # Wait a moment for the frontend to spin up
        time.sleep(5)
        
        # 3. Start ngrok tunnel for the frontend
        print("[*] Starting ngrok tunnel for frontend (Port 5173)...")
        frontend_tunnel = ngrok.connect(5173, bind_tls=True)
        print(f"[+] Frontend Tunnel established at: {frontend_tunnel.public_url}")
        
        print("\n=======================================================")
        print(f"🚀 LIVE FRONTEND URL: {frontend_tunnel.public_url}")
        print(f"🔌 LIVE BACKEND URL:  {backend_url}")
        print("=======================================================\n")
        
        print("[*] Tunnels are active. Keep this script running (Ctrl+C to quit).")
        
        # Keep the python script alive so the tunnels stay open
        ngrok_process = ngrok.get_ngrok_process()
        ngrok_process.proc.wait()
        
    except Exception as e:
        print(f"Error: {e}")
        print("\nIf ngrok is asking for an authtoken, run:")
        print("  ngrok config add-authtoken <your-token>")

if __name__ == "__main__":
    main()
