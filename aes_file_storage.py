import os
import hashlib
from cryptography.fernet import Fernet
import datetime

KEY_FILE = "secret.key"
META_FILE = "metadata.txt"

# Generate key
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print("Key generated and saved as secret.key")

# Load key
def load_key():
    return open(KEY_FILE, "rb").read()

# Hash file
def hash_file(filename):
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# Encrypt file
def encrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)

    with open(filename, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    enc_file = filename + ".enc"
    with open(enc_file, "wb") as f:
        f.write(encrypted)

    file_hash = hash_file(filename)

    with open(META_FILE, "a") as meta:
        meta.write(f"{filename}|{enc_file}|{file_hash}|{datetime.datetime.now()}\n")

    print("File encrypted:", enc_file)

# Decrypt file
def decrypt_file(enc_file):
    key = load_key()
    fernet = Fernet(key)

    with open(enc_file, "rb") as f:
        encrypted = f.read()

    decrypted = fernet.decrypt(encrypted)

    output_file = "decrypted_" + enc_file.replace(".enc", "")
    with open(output_file, "wb") as f:
        f.write(decrypted)

    print("File decrypted:", output_file)

# Verify integrity
def verify_file(filename):
    current_hash = hash_file(filename)
    with open(META_FILE, "r") as meta:
        for line in meta:
            original, enc, stored_hash, time = line.strip().split("|")
            if original == filename:
                if stored_hash == current_hash:
                    print("File integrity verified. No tampering.")
                else:
                    print("Warning: File has been tampered!")
                return
    print("No metadata found.")

# Menu
def menu():
    while True:
        print("\nAES Secure File Storage")
        print("1. Generate Key")
        print("2. Encrypt File")
        print("3. Decrypt File")
        print("4. Verify File Integrity")
        print("5. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            generate_key()
        elif choice == "2":
            file = input("Enter file name: ")
            encrypt_file(file)
        elif choice == "3":
            file = input("Enter encrypted file name: ")
            decrypt_file(file)
        elif choice == "4":
            file = input("Enter original file name: ")
            verify_file(file)
        elif choice == "5":
            break
        else:
            print("Invalid choice")

menu()