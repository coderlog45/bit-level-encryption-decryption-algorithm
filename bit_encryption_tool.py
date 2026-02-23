# bit_encryption_tool.py
# Bit-level (byte-wise) multi-key encryption/decryption with a Tkinter GUI.
# Text mode uses Base64 so encrypted bytes can be shown in the textbox.
# File mode processes any file (pdf/jpg/txt/…) and saves to disk.

import tkinter as tk
from tkinter import filedialog, messagebox
import base64
import os
from typing import List

# ------------------------- Low-level crypto helpers -------------------------

def _rotl_byte(b: int, r: int) -> int:
    """Rotate left an 8-bit integer by r bits."""
    r &= 7  # keep within 0..7
    return ((b << r) & 0xFF) | (b >> (8 - r)) if r else b

def _rotr_byte(b: int, r: int) -> int:
    """Rotate right an 8-bit integer by r bits."""
    r &= 7
    return ((b >> r) | ((b << (8 - r)) & 0xFF)) if r else b

def _round_encrypt(data: bytearray, key: int) -> None:
    """
    One reversible 'round':
      1) XOR each byte with (key & 0xFF)
      2) Rotate each byte left by (key % 8) bits
    (In-place)
    """
    k8 = key & 0xFF
    r = key & 7
    for i in range(len(data)):
        data[i] ^= k8
        data[i] = _rotl_byte(data[i], r)

def _round_decrypt(data: bytearray, key: int) -> None:
    """
    Inverse of _round_encrypt:
      1) Rotate each byte right by (key % 8)
      2) XOR with (key & 0xFF)
    (In-place)
    """
    k8 = key & 0xFF
    r = key & 7
    for i in range(len(data)):
        data[i] = _rotr_byte(data[i], r)
        data[i] ^= k8

def encrypt_bytes(data: bytes, keys: List[int]) -> bytes:
    """
    Apply multiple encryption rounds sequentially.
    """
    buf = bytearray(data)
    for k in keys:
        _round_encrypt(buf, k)
    return bytes(buf)

def decrypt_bytes(data: bytes, keys: List[int]) -> bytes:
    """
    Decrypt by applying inverse rounds in reverse key order.
    """
    buf = bytearray(data)
    for k in reversed(keys):
        _round_decrypt(buf, k)
    return bytes(buf)

# ------------------------- Tkinter GUI logic -------------------------

def parse_keys(raw: str) -> List[int]:
    ks = raw.strip().split()
    if not ks:
        raise ValueError("Enter at least one key (space-separated integers).")
    try:
        keys = [int(x) for x in ks]
    except ValueError:
        raise ValueError("Keys must be integers (e.g. 3 7 12).")
    return keys

def do_encrypt_text():
    try:
        keys = parse_keys(key_entry.get())
        plain = input_text.get("1.0", tk.END).rstrip("\n")
        if not plain:
            messagebox.showerror("Error", "Please enter some text to encrypt.")
            return
        data = plain.encode("utf-8")
        enc = encrypt_bytes(data, keys)
        # Base64 so it’s displayable and easy to copy/paste
        out_b64 = base64.b64encode(enc).decode("ascii")
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, out_b64)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def do_decrypt_text():
    try:
        keys = parse_keys(key_entry.get())
        b64 = input_text.get("1.0", tk.END).strip()
        if not b64:
            messagebox.showerror("Error", "Paste Base64 encrypted text to decrypt.")
            return
        enc = base64.b64decode(b64, validate=True)
        dec = decrypt_bytes(enc, keys)
        out = dec.decode("utf-8", errors="replace")
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, out)
    except base64.binascii.Error:
        messagebox.showerror("Error", "Invalid Base64 input.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def do_encrypt_file():
    try:
        keys = parse_keys(key_entry.get())
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return

    in_path = filedialog.askopenfilename(title="Select file to encrypt")
    if not in_path:
        return

    try:
        with open(in_path, "rb") as f:
            data = f.read()
        enc = encrypt_bytes(data, keys)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read/encrypt file:\n{e}")
        return

    default_name = os.path.basename(in_path) + ".enc"
    out_path = filedialog.asksaveasfilename(
        title="Save Encrypted File",
        initialfile=default_name,
        defaultextension=".enc",
        filetypes=[("Encrypted file", "*.enc"), ("All files", "*.*")]
    )
    if not out_path:
        return

    try:
        with open(out_path, "wb") as f:
            f.write(enc)
        messagebox.showinfo("Success", f"Encrypted file saved:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save file:\n{e}")

def do_decrypt_file():
    try:
        keys = parse_keys(key_entry.get())
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return

    in_path = filedialog.askopenfilename(title="Select file to decrypt")
    if not in_path:
        return

    try:
        with open(in_path, "rb") as f:
            data = f.read()
        dec = decrypt_bytes(data, keys)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read/decrypt file:\n{e}")
        return

    # Let the user choose any extension; they know the original type.
    out_path = filedialog.asksaveasfilename(
        title="Save Decrypted File",
        filetypes=[("All files", "*.*")]
    )
    if not out_path:
        return

    try:
        with open(out_path, "wb") as f:
            f.write(dec)
        messagebox.showinfo("Success", f"Decrypted file saved:\n{out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save file:\n{e}")

def on_encrypt():
    if file_mode.get():
        do_encrypt_file()
    else:
        do_encrypt_text()

def on_decrypt():
    if file_mode.get():
        do_decrypt_file()
    else:
        do_decrypt_text()

# ------------------------- Build the UI -------------------------

root = tk.Tk()
root.title("Bit-Level Multi-Key Encryption Tool")
root.geometry("760x580")
root.configure(bg="#f5f5f5")

title = tk.Label(root, text="Bit-Level Multi-Key Encryption Tool",
                 font=("Segoe UI", 16, "bold"), bg="#f5f5f5")
title.pack(pady=12)

file_mode = tk.BooleanVar(value=False)
file_chk = tk.Checkbutton(root, text="File Mode (Encrypt/Decrypt Files)",
                          variable=file_mode, bg="#f5f5f5", font=("Segoe UI", 11))
file_chk.pack()

lbl_in = tk.Label(root, text="Enter Text (for Text Mode) OR Base64 (for Decrypt):",
                  font=("Segoe UI", 11), bg="#f5f5f5")
lbl_in.pack(pady=(10, 4))

input_text = tk.Text(root, height=8, width=90, wrap="word")
input_text.pack(padx=16)

lbl_keys = tk.Label(root, text="Enter Keys (space separated integers, e.g. 3 7 12):",
                    font=("Segoe UI", 11), bg="#f5f5f5")
lbl_keys.pack(pady=(12, 4))

key_entry = tk.Entry(root, width=50, font=("Segoe UI", 11))
key_entry.pack()

btn_frame = tk.Frame(root, bg="#f5f5f5")
btn_frame.pack(pady=14)

btn_encrypt = tk.Button(btn_frame, text="Encrypt", width=16, font=("Segoe UI", 11, "bold"),
                        bg="#4CAF50", fg="white", command=on_encrypt)
btn_encrypt.grid(row=0, column=0, padx=10)

btn_decrypt = tk.Button(btn_frame, text="Decrypt", width=16, font=("Segoe UI", 11, "bold"),
                        bg="#2196F3", fg="white", command=on_decrypt)
btn_decrypt.grid(row=0, column=1, padx=10)

lbl_out = tk.Label(root, text="Output (Base64 in Text Mode):",
                   font=("Segoe UI", 11), bg="#f5f5f5")
lbl_out.pack()

output_text = tk.Text(root, height=8, width=90, wrap="word")
output_text.pack(padx=16, pady=(4, 12))

note = tk.Label(
    root,
    text="Notes:\n• Text Mode encrypts to Base64 (copy/paste friendly). Use the same keys to decrypt.\n"
         "• File Mode works with any file type. Choose a file and a save location.\n"
         "• Multi-key security: each key adds an XOR and bit-rotation round.",
    justify="left", bg="#f5f5f5", font=("Segoe UI", 9)
)
note.pack(padx=16)

root.mainloop()
