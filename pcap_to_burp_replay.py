#!/usr/bin/env python3
# This tool is part of the OpenBash project - https://www.openbash.com
# Making pentesters' daily work easier, one tool at a time.

import os
import subprocess
import requests
import tempfile
from pathlib import Path

def extraer_http_con_tcpflow(pcap_file, output_dir):
    print(f"[+] Extracting HTTP traffic from {pcap_file} with tcpflow...")
    try:
        subprocess.run(["tcpflow", "-r", pcap_file, "-o", output_dir], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running tcpflow: {e}")
        exit(1)

def reconstruir_requests(output_dir):
    print("[+] Reconstructing valid HTTP requests...")
    requests_http = []
    for archivo in Path(output_dir).glob("*"):
        try:
            contenido = archivo.read_text(errors="ignore").strip()
            if contenido.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")):
                requests_http.append(contenido)
        except Exception as e:
            print(f"[!] Error reading {archivo}: {e}")
    print(f"[+] Total valid HTTP requests found: {len(requests_http)}")
    return requests_http

def enviar_a_burp(requests_http):
    print("[+] Sending requests through Burp proxy at 127.0.0.1:8080...")

    proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    }

    for idx, raw in enumerate(requests_http):
        lines = raw.splitlines()
        if len(lines) < 1:
            continue

        primera_linea = lines[0].strip()
        partes = primera_linea.split()
        if len(partes) < 3:
            print(f"[!] Malformed request #{idx}: {primera_linea}")
            continue

        method, path, _ = partes[:3]
        headers = {}
        body = ""
        in_body = False

        for line in lines[1:]:
            if line.strip() == "":
                in_body = True
                continue
            if in_body:
                body += line + "\n"
            else:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k] = v

        if 'Host' not in headers:
            print(f"[!] Request #{idx} missing Host header.")
            continue

        for scheme in ["http", "https"]:
            url = f"{scheme}://{headers['Host']}{path}"
            print(f"[>] {method} {url}")
            try:
                requests.request(method, url, headers=headers, data=body, proxies=proxies, verify=False, timeout=10)
            except Exception as e:
                print(f"[!] Error sending to {url}: {e}")

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_to_burp_replay.py <capture.pcap>")
        exit(1)

    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(f"[!] File {pcap_file} not found.")
        exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        extraer_http_con_tcpflow(pcap_file, tmpdir)
        requests_http = reconstruir_requests(tmpdir)
        enviar_a_burp(requests_http)

if __name__ == "__main__":
    main()
