import tkinter as tk
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Fungsi untuk mengenkripsi pesan
def encrypt_message():
    global key
    key = get_random_bytes(16)  # Generate random 16-byte key
    message = message_entry.get()  # Ambil pesan dari input
    
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    
    iv_output_label.insert(tk.END, "IV: " + iv)
    ciphertext_output_label.insert(tk.END, "Ciphertext: " + ct)

# Fungsi untuk mendekripsi pesan
def decrypt_message():
    global key
    iv = iv_entry.get()  # Ambil IV dari input
    ciphertext = ciphertext_entry.get()  # Ambil ciphertext dari input
    
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    
    plaintext_output_label.config(text="Plaintext: " + pt.decode('utf-8'))

# Membuat aplikasi Tkinter
root = tk.Tk()
root.title("AES Encryption/Decryption")

# Membuat label dan entry untuk pesan
message_label = tk.Label(root, text="Message:")
message_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
message_entry = tk.Entry(root, width=50)
message_entry.grid(row=0, column=1, padx=5, pady=5)

# Tombol untuk mengenkripsi
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_message)
encrypt_button.grid(row=1, column=0, padx=5, pady=5)

# Label untuk menampilkan IV dan ciphertext (hanya untuk enkripsi)
iv_output_label = tk.Entry(root, width=37)
iv_output_label.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
ciphertext_output_label = tk.Entry(root, width=37)
ciphertext_output_label.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

# Membuat label dan entry untuk IV (hanya untuk dekripsi)
iv_label = tk.Label(root, text="IV:")
iv_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")
iv_entry = tk.Entry(root, width=50)
iv_entry.grid(row=4, column=1, padx=5, pady=5)

# Membuat label dan entry untuk ciphertext (hanya untuk dekripsi)
ciphertext_label = tk.Label(root, text="Ciphertext:")
ciphertext_label.grid(row=5, column=0, padx=5, pady=5, sticky="w")
ciphertext_entry = tk.Entry(root, width=50)
ciphertext_entry.grid(row=5, column=1, padx=5, pady=5)

# Tombol untuk mendekripsi
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_message)
decrypt_button.grid(row=6, column=0, padx=5, pady=5)

# Label untuk menampilkan plaintext (hanya untuk dekripsi)
plaintext_output_label = tk.Label(root, text="")
plaintext_output_label.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()
