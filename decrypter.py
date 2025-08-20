#!/usr/bin/env python3
# decrypter_smart.py
# Smart vault fetcher + decryptor that works with:
#  - Fernet-encrypted vault.enc (binary)
#  - XOR-LCG hex vault.enc (the earlier make_vault.py format)
#
# It asks Arduino for a secret (may be either a Fernet key or a passphrase).
# If the secret isn't a valid Fernet key the script will derive one from it
# (sha256 -> urlsafe_base64). If Fernet fails, it also attempts the XOR-LCG
# decrypt (for legacy vaults saved as hex).
#
# Usage: python decrypter_smart.py
#
# Dependencies:
#   pip install pyserial requests cryptography rich

import re
import time
import hashlib
import base64
import json
import sys
from pathlib import Path

import requests
import serial
from cryptography.fernet import Fernet, InvalidToken
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress

console = Console()

# ----------------- helpers -----------------
def to_raw_github(url: str) -> str:
    """Convert a GitHub blob URL to raw.githubusercontent URL when possible."""
    if not url:
        return url
    url = url.strip()
    if "github.com" in url and "/blob/" in url:
        # https://github.com/user/repo/blob/branch/path -> https://raw.githubusercontent.com/user/repo/branch/path
        return url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")
    return url

def fetch_url_bytes(url: str, timeout=15) -> bytes:
    url2 = to_raw_github(url)
    console.print(f"[cyan]Using URL:[/cyan] {url2}")
    r = requests.get(url2, timeout=timeout)
    r.raise_for_status()
    return r.content

# --- XOR-LCG (legacy) helpers (matches make_vault.py / Arduino sketch)
def djb2_seed(s: str) -> int:
    h = 5381
    for ch in s:
        h = ((h << 5) + h) + ord(ch)
        h &= 0xFFFFFFFF
    return h

def kstream(seed: int, nbytes: int) -> bytes:
    v = seed & 0xFFFFFFFF
    out = bytearray()
    for _ in range(nbytes):
        v = (v * 1664525 + 1013904223) & 0xFFFFFFFF
        out.append(v & 0xFF)
    return bytes(out)

def xor_decrypt_from_hex(hextext: str, password: str) -> bytes:
    """Given hex-string ciphertext and a textual password, return plaintext bytes."""
    b = bytes.fromhex(hextext.strip())
    ks = kstream(djb2_seed(password), len(b))
    return bytes(x ^ k for x, k in zip(b, ks))

# ----------------- Serial/Arduino -----------------
def open_serial_prompt() -> serial.Serial:
    port = input("Enter Arduino serial port (e.g. COM3 or /dev/ttyACM0) [default COM3]: ").strip() or "COM3"
    baud_in = input("Enter baud (try 9600 or 115200) [default 9600]: ").strip() or "9600"
    try:
        baud = int(baud_in)
    except:
        baud = 9600
    console.print(f"[cyan]Opening {port} @ {baud}...[/cyan]")
    try:
        ser = serial.Serial(port, baud, timeout=4)
        time.sleep(1.2)  # allow Arduino reset if applicable
        return ser
    except Exception as e:
        console.print(f"[red]Failed to open serial port:[/red] {e}")
        return None

def request_secret_from_arduino(ser: serial.Serial, tries=3) -> str:
    """
    Try several common request commands and return the first non-empty line.
    The sketch you upload should respond to one of these (case-insensitive):
     - GET_KEY, GETKEY, KEY, GET_KEY\n etc
    """
    cmds = [b"GET_KEY\n", b"GETKEY\n", b"KEY\n", b"GETKEY", b"KEY", b"GET_KEY"]
    ser.reset_input_buffer()
    for c in cmds:
        try:
            ser.write(c)
            time.sleep(0.15)
            # read a couple lines
            for _ in range(6):
                line = ser.readline().decode(errors="ignore").strip()
                if line:
                    # ignore obvious prompts like "PIN?" — if it's a prompt, we stop and let user handle
                    if line.upper().startswith("PIN?"):
                        console.print("[yellow]Arduino asked for PIN. Please open a serial terminal to complete PIN auth (or use an Arduino sketch that sends key directly).[/yellow]")
                        raise RuntimeError("PIN required")
                    # if line starts with KEY: strip label
                    if line.upper().startswith("KEY:"):
                        return line[4:].strip()
                    return line
        except RuntimeError:
            raise
        except Exception:
            pass
    # if nothing returned, try a manual read wait
    deadline = time.time() + 3.0
    while time.time() < deadline:
        line = ser.readline().decode(errors="ignore").strip()
        if line:
            if line.upper().startswith("KEY:"):
                return line[4:].strip()
            return line
    raise RuntimeError("No key received from Arduino (no response)")

# ----------------- Decryption attempts -----------------
def try_fernet_decrypt(key: str, enc_bytes: bytes):
    """Try to decrypt as Fernet. Returns plaintext bytes or raises."""
    try:
        # if key looks like a passphrase (not 44 chars), derive a Fernet key from it automatically
        k = key.strip()
        if not re.fullmatch(r'[A-Za-z0-9_\-]{43,44}={0,2}', k):
            # derive from passphrase (sha256 -> urlsafe_b64)
            h = hashlib.sha256(k.encode("utf-8")).digest()
            k = base64.urlsafe_b64encode(h).decode("utf-8")
            console.print("[dim]Derived Fernet key from provided secret (sha256 -> urlsafe_b64)[/dim]")
        f = Fernet(k.encode("utf-8"))
        pt = f.decrypt(enc_bytes)
        return pt
    except InvalidToken:
        raise
    except Exception as e:
        # pass error upward for diagnostics
        raise

def try_xor_hex_decrypt(key: str, enc_bytes: bytes):
    """If enc_bytes is actually an ASCII hex string (legacy), try XOR-LCG decryption."""
    try:
        text = enc_bytes.decode("utf-8").strip()
    except Exception:
        return None
    # ensure looks like hex
    if not re.fullmatch(r'[0-9a-fA-F]+\s*', text):
        return None
    try:
        pt = xor_decrypt_from_hex(text, key)
        return pt
    except Exception:
        return None

# ----------------- Main -----------------
def main():
    console.print(Panel("[bold cyan]Arduino-Smart Vault Decrypter[/bold cyan]", expand=False))

    # 1) get GitHub URL (accept blob or raw)
    default_url = "https://github.com/Casliyan/steamshifofreeniga/blob/main/vault.enc"
    url = input(f"Enter vault URL (GitHub blob/raw) [{default_url}]: ").strip() or default_url
    try:
        console.print("[cyan]Downloading vault.enc...[/cyan]")
        enc_bytes = fetch_url_bytes(url)
    except Exception as e:
        console.print(f"[red]Failed to download vault.enc:[/red] {e}")
        return

    # quick detection: if we've downloaded an HTML page by mistake, warn & attempt raw conversion
    if b"<html" in enc_bytes[:200].lower():
        console.print("[yellow]Downloaded content looks like HTML (GitHub page). Trying to convert to raw URL...[/yellow]")
        raw = to_raw_github(url)
        try:
            enc_bytes = fetch_url_bytes(raw)
        except Exception as e:
            console.print(f"[red]Still failed to fetch raw file:[/red] {e}")
            return

    # 2) open serial and request key
    ser = open_serial_prompt()
    if ser is None:
        return

    try:
        secret = request_secret_from_arduino(ser)
        console.print(f"[green]Received secret from Arduino:[/green] {secret[:40]}{'...' if len(secret)>40 else ''}")
    except RuntimeError as e:
        console.print(f"[red]Error getting secret from Arduino:[/red] {e}")
        ser.close()
        return
    except Exception as e:
        console.print(f"[red]Serial error:[/red] {e}")
        ser.close()
        return

    # 3) Try Fernet first (either direct or derived)
    decrypted = None
    with console.status("[cyan]Attempting Fernet decryption...[/cyan]"):
        try:
            decrypted = try_fernet_decrypt(secret, enc_bytes)
            console.print("[green]Fernet decryption succeeded.[/green]")
        except InvalidToken:
            console.print("[yellow]Fernet decryption failed (invalid token).[ /yellow]")
        except Exception as e:
            console.print(f"[yellow]Fernet attempt error:[/yellow] {e}")

    # 4) If Fernet failed, try XOR-LCG legacy (hex)
    if decrypted is None:
        console.print("[cyan]Trying legacy XOR-LCG (hex vault) decryption...[/cyan]")
        try:
            pt = try_xor_hex_decrypt(secret, enc_bytes)
            if pt:
                # verify magic header "VAULT\n"
                if pt.startswith(b"VAULT\n"):
                    decrypted = pt[len(b"VAULT\n"):]
                    console.print("[green]Legacy XOR-LCG decryption succeeded.[/green]")
                else:
                    # still present the raw plaintext to inspection
                    decrypted = pt
                    console.print("[yellow]XOR-LCG produced plaintext but header missing — showing raw output.[/yellow]")
            else:
                console.print("[red]XOR-LCG attempt not applicable or failed.[/red]")
        except Exception as e:
            console.print(f"[red]XOR-LCG attempt error:[/red] {e}")

    # 5) result handling
    if decrypted is None:
        console.print("[bold red]All decryption attempts failed.[/bold red]")
        console.print("Tips:")
        console.print("- Ensure Arduino is sending the correct secret (a valid Fernet key or the original passphrase).")
        console.print("- If you used Fernet to encrypt vault.enc, Arduino's secret must be the 44-char urlsafe base64 key OR a passphrase you derived the key from.")
        console.print("- If vault.enc is the old hex format (created by make_vault.py), Arduino should supply the same password used originally.")
        ser.close()
        return

    # 6) presentation
    try:
        text = decrypted.decode("utf-8", errors="replace")
        console.print(Panel.fit("[bold green]Decrypted Vault Content[/bold green]"))

        # pretty-print JSON if it looks like JSON
        try:
            parsed = json.loads(text)
            console.print(json.dumps(parsed, indent=2))
        except Exception:
            console.print(text)
    finally:
        ser.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Cancelled by user.[/red]")
        sys.exit(0)
