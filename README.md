# [Cipher Guard: Encrypt with Confidence!](https://github.com/Sanjai-Flora/Cipher-Guard.git) 

![intel](https://github.com/user-attachments/assets/0f7efebd-789d-4774-ad13-b2f7e19f0174)

## Problem Statement
Protecting the user password keys at rest (on the Disk)

Develop an authorization application which in turn protects the password keys. Following are the high level feature
- Encrypt [AES-256] a user chosen file or directory using a random key a.k.a File Encryption Key
- Store the random key in a file which has to be protected via user pass phrase.
- The user pass phrase as well as the random key can not be stored in plain form in the text file.
- If the user pass phrase authentication is successful retrieve i.e decrypt the file using File Encryption Key

## Description
**Cipher Guard** is a user-friendly file and folder encryption application built with Python, PyQt5, and robust cryptographic libraries like Argon2id, Scrypt, ChaCha20-Poly1305, and AES-256-GCM. It empowers users to safeguard their digital world with strong encryption and a streamlined interface.

## Key Features

- Strong encryption (AES-256-GCM or ChaCha20-Poly1305)
- Secure key protection (Argon2id, scrypt)
- Encrypt files/folders
- Easy-to-use interface
- Password strength checker
- Secure notes storage
- Activity history
- Password protected settings

## Screenshots

## How to Use:

### Installation:

### 1. Clone the repository
```
https://github.com/Sanjai-Flora/Cipher-Guard.git
```

### 2. Navigate to the project directory
```
cd Cipher-Guard
```

### 3. Install the required libraries
```
pip install -r requirements.txt
```

### 4. Running the Application:
 ```
 main.py
```

### Using Cipher Guard:

- Entering a Passphrase: Type a strong passphrase. A strength indicator will guide you.
- Choosing an Algorithm: Select AES-256-GCM or ChaCha20-Poly1305.
- Selecting Files/Folders: Use "Select File(s)" or "Select Folder."
- Encrypting/Decrypting: Click "Encrypt" or "Decrypt" and confirm your passphrase. A progress bar will show the status.
- Notes: Securely store sensitive text using the "Note" button.
- History: View your encryption/decryption history.

## Security Considerations:

- Passphrase Strength: Use a strong and unique passphrase for maximum security.
- Password Management: Store your passphrase securely. Forgetting it will result in permanent data loss.
- Backup Your Data: Always maintain backups of your important files, as encryption is not a substitute for a comprehensive backup strategy.

## Disclaimer:
This application is provided "as is" without warranty of any kind, express or implied. Use it at your own risk. The developers are not responsible for any data loss or damage that may occur.
