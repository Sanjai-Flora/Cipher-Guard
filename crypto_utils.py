import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.backends import default_backend
import argon2
from datetime import datetime
import pickle

# Function to generate a key using Argon2id.
def derive_key_argon2id(passphrase, salt):
# Use Argon2id to generate a key from the passphrase and salt.
    kdf = argon2.low_level.hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )
    return kdf

# Function to generate a key using scrypt.
def derive_key_scrypt(passphrase, salt):
# Use scrypt to generate a key from the passphrase and salt.       
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# Function for encrypting the File Encryption Key (FEK) with the derived key
def encrypt_fek(fek, derived_key, algorithm):
# Select the cipher based on the selected algorithm.
    if algorithm == "ChaCha20-Poly1305":
        cipher = ChaCha20Poly1305(derived_key)
    else:  # AES-256-GCM
        cipher = AESGCM(derived_key)
    nonce = os.urandom(12)
    # Encrypt the FEK with the chosen cipher.
    ciphertext = cipher.encrypt(nonce, fek, None)
    return nonce + ciphertext

# Function for decrypting the File Encryption Key (FEK) with the derived key
def decrypt_fek(encrypted_fek, derived_key, algorithm):
# Select the cipher based on the selected algorithm.
    if algorithm == "ChaCha20-Poly1305":
        cipher = ChaCha20Poly1305(derived_key)
    else:  # AES-256-GCM
        cipher = AESGCM(derived_key)
    nonce = encrypted_fek[:12]
    ciphertext = encrypted_fek[12:]
    try:
        # Decrypt the FEK with the chosen cipher
        return cipher.decrypt(nonce, ciphertext, None)
    except ValueError:
        raise ValueError("Incorrect passphrase or corrupted data")


# Function to encrypt a file using the File Encryption Key (FEK)
def encrypt_file(file_path, fek, algorithm, progress_callback=None):
    # Select the cipher based on the selected algorithm.
    if algorithm == "ChaCha20-Poly1305":
        cipher = ChaCha20Poly1305(fek)
    else:  # AES-256-GCM
        cipher = AESGCM(fek)

    nonce = os.urandom(12)
    chunk_size = 64 * 1024 * 1024  # 64 MB chunks

    encrypted_file_path = file_path + '.encrypted'
    file_size = os.path.getsize(file_path)

    with open(file_path, 'rb') as in_file, open(encrypted_file_path, 'wb') as out_file:
        # Place the nonce at the beginning of the file.
        out_file.write(nonce)

        # Encrypt and write the file's size
        encrypted_size = cipher.encrypt(nonce, str(file_size).encode(), None)
        out_file.write(len(encrypted_size).to_bytes(4, byteorder='big'))
        out_file.write(encrypted_size)

        bytes_read = 0
        while True:
            chunk = in_file.read(chunk_size)
            if len(chunk) == 0:
                break
            encrypted_chunk = cipher.encrypt(nonce, chunk, None)
            out_file.write(len(encrypted_chunk).to_bytes(4, byteorder='big'))
            out_file.write(encrypted_chunk)
            bytes_read += len(chunk)
            if progress_callback:
                progress_callback(bytes_read, file_size)

    # Delete the original file
    os.remove(file_path)

# Function for decrypting a file using the File Encryption Key (FEK)
def decrypt_file(file_path, fek, algorithm, progress_callback=None):
# Select the cipher based on the selected algorithm.
    if algorithm == "ChaCha20-Poly1305":
        cipher = ChaCha20Poly1305(fek)
    else:  # AES-256-GCM
        cipher = AESGCM(fek)

    decrypted_file_path = file_path[:-10]  # Remove '.encrypted' extension

    with open(file_path, 'rb') as in_file, open(decrypted_file_path, 'wb') as out_file:
        # Read the nonce at the beginning of the file.
        nonce = in_file.read(12)

        # Decrypt the file and read its size.
        size_len = int.from_bytes(in_file.read(4), byteorder='big')
        encrypted_size = in_file.read(size_len)
        file_size = int(cipher.decrypt(nonce, encrypted_size, None))

        bytes_written = 0
        while bytes_written < file_size:
            chunk_len = int.from_bytes(in_file.read(4), byteorder='big')
            encrypted_chunk = in_file.read(chunk_len)
            decrypted_chunk = cipher.decrypt(nonce, encrypted_chunk, None)
            out_file.write(decrypted_chunk)
            bytes_written += len(decrypted_chunk)
            if progress_callback:
                progress_callback(bytes_written, file_size)

    # Delete the encrypted file
    os.remove(file_path)

# Function to encrypt a folder sequentially using the File Encryption Key (FEK)
def encrypt_folder(folder_path, fek, algorithm, progress_callback=None):
    total_size = 0
    for root, _, files in os.walk(folder_path):
        for file in files:
            total_size += os.path.getsize(os.path.join(root, file))

    bytes_processed = 0
    def folder_progress_callback(bytes_read, file_size):
        nonlocal bytes_processed
        bytes_processed += bytes_read
        if progress_callback:
            progress_callback(bytes_processed, total_size)

# Walk through the folder and encrypt every file.
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, fek, algorithm, folder_progress_callback)

    # Rename the folder to show that it is encrypted.
    encrypted_folder_path = folder_path + '.encrypted'
    os.rename(folder_path, encrypted_folder_path)

# Function to decrypt a folder sequentially using the File Encryption Key (FEK)
def decrypt_folder(folder_path, fek, algorithm, progress_callback=None):
    total_size = 0
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.encrypted'):
                total_size += os.path.getsize(os.path.join(root, file))

    bytes_processed = 0
    def folder_progress_callback(bytes_read, file_size):
        nonlocal bytes_processed
        bytes_processed += bytes_read
        if progress_callback:
            progress_callback(bytes_processed, total_size)

    # Walk through the folder and decrypt every file.
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.encrypted'):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, fek, algorithm, folder_progress_callback)
    # Rename the folder to remove the '.encrypted' extension
    decrypted_folder_path = folder_path[:-10]  
    os.rename(folder_path, decrypted_folder_path)

# Function for tracking history.
def update_history(action, file_paths, hidden_dir):
    history_file = os.path.join(hidden_dir, 'history.bin')
    entries = [{
        "action": action,
        "file_path": file_path,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    } for file_path in file_paths]
    
    if os.path.exists(history_file):
        with open(history_file, 'rb') as file:
            history = pickle.load(file)
    else:
        history = []
        
    history.extend(entries)
    
    with open(history_file, 'wb') as file:
        pickle.dump(history, file)
