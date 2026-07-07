🔑 **Unicode Password Utility**

[![unigen.jpg](https://i.postimg.cc/kg0KKsq1/unigen.jpg)](https://postimg.cc/87b7VhFM)

The Unicode Password Utility is a Python 3 script designed for generating cryptographically strong, high-entropy passwords using an extensive Unicode character pool and managing them securely through file encryption.

It leverages the modern cryptography library (Fernet, AES-128 GCM) and prioritizes security by integrating methods for secure file deletion to ensure plain-text passwords are not left on disk.

✨ **Key Features**

1. High-Entropy Generation: Generates passwords using a vast pool of over 400 unique Unicode characters (Latin, Cyrillic, CJK, Math Symbols, Dingbats, etc.).

2. Cryptographic Security: Uses Fernet (built on AES-128 GCM) for strong encryption of saved password files, secured by a user-provided password.

3. Password Strength Rating: Calculates and displays the logarithmic entropy (in bits) of generated passwords.

4. Secure Deletion: Employs the external shred utility (Linux/macOS) or a robust Python-native secure overwrite mechanism as a fallback to destroy temporary and decrypted plain-text files.

5. Integrated Editor: Allows users to specify and launch an external text editor (like nano, vi, or notepad) immediately after decryption for easy modification before re-encryption.

🛠 **Prerequisites**

To run this utility, you need:

Python 3.6+

The cryptography library.

🚀 **Installation**

1. Download Script

```wget https://raw.githubusercontent.com/A113L/Unicode-Password-Generator-Bash-Script/refs/heads/main/unigen.py```


2. Install Dependencies

You only need the cryptography library:

```pip install cryptography```


3. (Optional) Check for shred

The script automatically prefers the shred utility for the most secure file deletion on Linux and macOS. If you are on Windows or shred is not available, the script will automatically use the built-in Python secure overwrite fallback.

💻 **Usage**

Run the script from your terminal:

```python3 unigen.py```


The script will prompt you to choose between two modes: (G)enerate or (D)ecrypt.

1. **Generate Mode (G)**

This mode creates new passwords and saves them securely.

*Choose (G)enerate.*

Enter the desired password length and count.

*Choose y to save to an ENCRYPTED file.*

The passwords are written to a temporary plain-text file (passwords_temp_*.txt).

You will be prompted to enter a strong encryption password.

The temporary file is encrypted to the final .enc file.

CRITICAL: The temporary plain-text file is then securely deleted.

2. **Decrypt Mode (D)**

This mode allows you to safely view and edit your stored passwords.

*Choose (D)ecrypt.*

Enter the name of your encrypted file (e.g., passwords_encrypted_*.enc).

Enter the decryption password.

The content is decrypted and written to a plain-text file (e.g., original_file_decrypted.txt).

The script will display the content and WARN you that the plain-text file is currently on disk.

You will be prompted to enter an editor command (e.g., nano, notepad, code) to edit the plain-text file.

After exiting the editor, you will be prompted to re-encrypt the file. Choosing y will:

Re-encrypt the edited content back to the original encrypted file.

SECURELY DELETE the plain-text decrypted file.

🔒 **Security Notes**

*Master Password:* The security of your encrypted file relies entirely on the strength of the encryption password you choose. Use a unique and very strong phrase for this.

*File Deletion:* While shred is the gold standard for secure file deletion on most Unix-like systems, the Python-native fallback provides a multi-pass overwrite using random data and zeros. Always verify that the script reports a successful secure deletion. If a "FATAL SECURITY WARNING" appears, the file may require manual secure deletion.

*Encryption Standard:* Fernet ensures authenticated encryption (integrity and confidentiality) using AES-128 GCM.
