# [Cipher Guard: Encrypt with Confidence!](https://github.com/Sanjai-Flora/Cipher-Guard.git) 

![intel](https://github.com/user-attachments/assets/0f7efebd-789d-4774-ad13-b2f7e19f0174)

## Problem Statement
Protecting the user password keys at rest (on the Disk)

Develop an authorization application which in turn protects the password keys. Following are the high level feature
- Encrypt [AES-256] a user chosen file or directory using a random key a.k.a File Encryption Key
- Store the random key in a file which has to be protected via user pass phrase.
- The user pass phrase as well as the random key can not be stored in plain form in the text file.
- If the user pass phrase authentication is successful retrieve i.e decrypt the file using File Encryption Key

🔒## Description
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

<table>
    <tr>
      <td>
        <img src="https://github.com/user-attachments/assets/3940e71c-8041-47e3-ad56-65cc26be2d7d" alt="splash_screen">
      </td>
      <td>
        <img src="https://github.com/user-attachments/assets/d1e9c003-ce3f-4b66-9e9a-7dd540d2431e" alt="login">
      </td>
    </tr>
    <tr>
      <td>
        <img src="https://github.com/user-attachments/assets/b4693d55-6f51-4f17-8e84-45607f098370" alt="main_screen">
      </td>
      <td>
        <img src="https://github.com/user-attachments/assets/dd536959-b60f-45dd-ab39-947caabf505c" alt="notes">
      </td>
    </tr>
    <tr>
      <td>
        <img src="https://github.com/user-attachments/assets/e86ddc6d-afb4-4764-abe6-9ca3521d8bc4" alt="history">
      </td>
      <td>
        <img src="https://github.com/user-attachments/assets/172f62a9-2cba-457c-8aa7-1511039ca436" alt="instructions">
      </td>
    </tr>
  </table>

## Key Resources
- [Demo Video](https://github.com/Sanjai-Flora/Cipher-Guard/blob/e3dde8a51d71390b13480d0b42721ccc6d18bc9b/demo.mp4)
- [Presentation](https://github.com/Sanjai-Flora/Cipher-Guard/blob/55c322562e3a4baf9ff8f12ed0f55a274e5328e5/presentation.pdf)

## How to Use

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
