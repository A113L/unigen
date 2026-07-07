"""
UNICODE Password Utility (Generator & Encrypter/Decrypter)

This script generates cryptographically secure passwords using a vast Unicode character pool.
It uses the Python 'cryptography' library (Fernet, AES-128 GCM) for cross-platform encryption.
It offers two modes:
1. Generate: Creates passwords and securely encrypts them to a file using a user-chosen
   password. The unencrypted temporary file is SECURELY DELETED using shred (Linux/macOS only).
2. Decrypt: Decrypts an existing password file. After viewing/editing, the plain-text file
   is re-encrypted and then SECURELY DELETED using shred or a Python-native fallback.

Requires 'cryptography' to be installed. 'shred' (Linux/macOS) is preferred for secure deletion.
"""
import string
import secrets
import math
import sys
import subprocess
import os
import getpass
from datetime import datetime
import platform # Added for platform detection

# --- Python Cryptography Imports (Replaces OpenSSL) ---
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- ANSI Color Codes ---
class Colors:
    """Class to hold ANSI escape codes for console output coloring."""
    RESET = '\033[0m'
    HEADER = '\033[95m'   # Magenta
    INFO = '\033[94m'     # Blue
    SUCCESS = '\033[92m'  # Green
    WARNING = '\033[93m'  # Yellow
    FAIL = '\033[91m'     # Red
    BOLD = '\033[1m'
    
def colored(text, color_code):
    """Wraps text in ANSI color codes."""
    return f"{color_code}{text}{Colors.RESET}"

# --- Configuration ---

# Character sets consolidated based on user request. All are combined for max entropy.
CHAR_SETS = {
    'Latin (Standard)': "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    'Latin (Extended)': "ąćęłńóśźżĄĆĘŁŃÓŚŹŻäöüßÄÖÜèéêëēėęùúûüūîïíīįìôöòóœøãåáàâæçñ",
    'Cyrillic': "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАВГДЕЁЖЗИЙКЛМНОПРСТФХЦЧШЩЪЫЬЭЮЯ",
    'Asian (CJK, Hiragana, Katakana)': "漢字日本語中文测试字符あいうえおかきくけこさしすせそたちつてとなにぬねのアイウエオカキクケコサシスセソタチツテトナニヌネノ",
    'Math/Symbols & Currency': "∞±≠∑∏√∫∂∆πµΩ≈≡≤≥∇¢£¥€₩₪₹₽฿₫₴₦₲",
    'Dingbats & Misc': "★☆☀☁☂☃☄☠☢☣♠♣♥♦♪♫✔✖✳❄‼",
    'Greek': "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδελμνξοπρςστυφχψω",
}

# Consolidate all characters into one pool string, removing duplicates using set()
UNICODE_POOL = "".join(set("".join(CHAR_SETS.values())))
POOL_SIZE = len(UNICODE_POOL)

# --- Crypto Functions ---

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from a password and salt using PBKDF2HMAC for Fernet."""
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000, # Recommended number of iterations for security
        backend=default_backend()
    )
    # Fernet keys must be 32 url-safe base64-encoded bytes
    return urlsafe_b64encode(kdf.derive(password_bytes))

def encrypt_file(input_file, output_file, key_password):
    """
    Encrypts an input file to an output file using Fernet (AES-128 GCM).
    The output file contains the salt (16 bytes) prepended to the Fernet token.
    """
    print(colored(f"\n--- Starting Fernet Encryption: {input_file} -> {output_file} ---", Colors.HEADER))
    
    # 1. Generate unique salt and derive key
    salt = os.urandom(16)
    key = derive_key(key_password, salt)
    f = Fernet(key)

    try:
        # 2. Read plaintext content (assuming it's UTF-8 text)
        with open(input_file, 'r', encoding='utf-8') as f_in_text:
            plaintext_content = f_in_text.read()

        # 3. Encrypt the content (Fernet works on bytes)
        plaintext_bytes = plaintext_content.encode('utf-8')
        encrypted_data = f.encrypt(plaintext_bytes)
        
        # 4. Write salt + encrypted data (binary mode)
        with open(output_file, 'wb') as f_out_binary:
            f_out_binary.write(salt)
            f_out_binary.write(encrypted_data)
        
        print(colored(f"Encryption successful! Content saved to '{output_file}'.", Colors.SUCCESS))

    except Exception as e:
        print(colored(f"❌ Encryption failed: {e}", Colors.FAIL))
        raise

# --- Utility Functions ---

def calculate_entropy(length, pool_size):
    """
    Calculates Logarithmic Entropy (Shannon H) in bits: H = L * log2(N), 
    where L is length and N is pool size.
    """
    if pool_size <= 1:
        return 0.00
    entropy = length * math.log2(pool_size)
    return round(entropy, 2)

def rate_entropy(entropy):
    """Rates password strength based on entropy bits and returns a colored string."""
    if entropy < 40:
        return colored("Very Weak", Colors.FAIL)
    elif entropy < 60:
        return colored("Weak", Colors.FAIL)
    elif entropy < 80:
        return colored("Moderate", Colors.WARNING)
    elif entropy < 100:
        return colored("Strong", Colors.SUCCESS)
    else:
        return colored("Very Strong", Colors.SUCCESS)

def generate_password(length):
    """Generates a secure password using secrets.choice for cryptographic randomness."""
    if length <= 0:
        return ""
    return ''.join(secrets.choice(UNICODE_POOL) for _ in range(length))

def _secure_overwrite_python_native(filepath, passes=3):
    """
    Python-native secure file overwrite using os.urandom and os.fsync.
    This overwrites file content with random data and zeros before deletion.
    """
    try:
        size = os.path.getsize(filepath)
    except OSError:
        # File might be gone or inaccessible
        return True # Treat as deleted if size can't be found/file is gone

    # 1. Overwrite with random data
    for _ in range(passes):
        try:
            # Open for reading and writing, keeping existing size
            with open(filepath, 'r+b') as f:
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno()) # Force write to disk
        except Exception:
            continue

    # 2. Overwrite with zeros (common final pass)
    try:
        with open(filepath, 'r+b') as f:
            f.seek(0)
            f.write(b'\0' * size)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass 

    # 3. Truncate and remove
    try:
        os.remove(filepath)
        return True
    except Exception:
        return False


def secure_delete(filepath):
    """
    Securely deletes a file using the 'shred' utility (preferred) or a Python-native fallback.
    """
    if not os.path.exists(filepath):
        return

    print(f"\nAttempting to securely delete: {filepath}")
    
    deleted_successfully = False
    
    # --- Attempt 1: Use shred (External Utility) ---
    try:
        if platform.system() in ('Linux', 'Darwin'): # Check for Linux or macOS
            shred_command = ['shred', '-n', '3', '-z', '-u', filepath]
            subprocess.run(shred_command, check=True, capture_output=True, text=True)
            print(colored("✅ Secure deletion via 'shred' successful.", Colors.SUCCESS))
            deleted_successfully = True
        else:
            raise FileNotFoundError("Platform does not support shred easily.")
        
    except FileNotFoundError:
        # shred not found or platform unsupported (e.g., Windows)
        print(colored("⚠️ 'shred' command not found or not supported on this platform.", Colors.WARNING))
        
        # --- Attempt 2: Python Native Overwrite ---
        print("Falling back to Python-native secure overwrite method.")
        if _secure_overwrite_python_native(filepath):
            print(colored("✅ Python-native secure overwrite and deletion successful.", Colors.SUCCESS))
            deleted_successfully = True
        else:
            # If native secure deletion failed, we must resort to standard delete
            print(colored(f"❌ Python-native secure overwrite failed. Falling back to os.remove().", Colors.FAIL))
            try:
                os.remove(filepath)
                print(f"Standard deletion of '{filepath}' complete (UNSECURE).")
                deleted_successfully = True
            except Exception as e_inner:
                print(colored(f"❌ Fatal Error: Could not delete file even with os.remove. Manual deletion required.", Colors.FAIL))
                print(colored(f"The vulnerable file '{filepath}' remains on disk! Error: {e_inner}", Colors.FAIL))

    except subprocess.CalledProcessError as e:
        # shred failed for other reason (e.g., permissions)
        print(colored(f"❌ 'shred' failed (Error: {e.stderr.strip()}). Falling back to Python-native overwrite.", Colors.FAIL))
        
        # Fallback to Python Native Overwrite
        if _secure_overwrite_python_native(filepath):
            print(colored("✅ Python-native secure overwrite and deletion successful.", Colors.SUCCESS))
            deleted_successfully = True
        else:
            # If native secure deletion failed, we must resort to standard delete
            print(colored(f"❌ Python-native secure overwrite failed. Falling back to os.remove().", Colors.FAIL))
            try:
                os.remove(filepath)
                print(f"Standard deletion of '{filepath}' complete (UNSECURE).")
                deleted_successfully = True
            except Exception as e_inner:
                print(colored(f"❌ Fatal Error: Could not delete file even with os.remove. Manual deletion required.", Colors.FAIL))
                print(colored(f"The vulnerable file '{filepath}' remains on disk! Error: {e_inner}", Colors.FAIL))
                
    if not deleted_successfully:
        print(colored(f"FATAL SECURITY WARNING: The file '{filepath}' may still exist on disk unsecurely.", Colors.FAIL + Colors.BOLD))


# --- Generator/Decryptor Logic ---

def run_generator():
    """Logic for generating and encrypting passwords."""
    print(colored("\n--- Unicode Password Generator (Python 3) ---", Colors.HEADER + Colors.BOLD))

    # 1. Get Password Length
    try:
        length = int(input("Enter desired password length (e.g., 20): ") or 20)
        if length < 1:
            print(colored("Error: Invalid length. Using default length of 20.", Colors.FAIL))
            length = 20
    except ValueError:
        print(colored("Error: Invalid length. Using default length of 20.", Colors.FAIL))
        length = 20

    # 2. Get Number of Passwords
    try:
        count = int(input("Enter number of passwords to generate (e.g., 3): ") or 3)
        if count < 1:
            print(colored("Error: Invalid count. Using default count of 3.", Colors.FAIL))
            count = 3
    except ValueError:
        print(colored("Error: Invalid count. Using default count of 3.", Colors.FAIL))
        count = 3

    # 3. Ask for File Save and Encryption
    save_choice = input("Do you want to save the passwords to an *ENCRYPTED* file? (y/n): ").strip().lower()
    save_file = ""
    temp_file = "" 

    if save_choice == 'y':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_file = f"passwords_encrypted_{timestamp}.enc"
        temp_file = f"passwords_temp_{timestamp}.txt"
        
        print(colored(f"Passwords will be saved to temporary file: {temp_file}", Colors.INFO))
        print(colored(f"Then encrypted to final file: {save_file}", Colors.INFO))
        
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write("--- Generated Passwords ---\n\n")
        except IOError:
            print(colored(f"Error: Could not open or write to temporary file {temp_file}.", Colors.FAIL))
            save_file = "" 
            temp_file = ""

    # Calculate Entropy
    entropy = calculate_entropy(length, POOL_SIZE)
    strength = rate_entropy(entropy)

    print(colored("\n--- Generation Parameters ---", Colors.BOLD))
    print(f"Character Pool Size: {POOL_SIZE} unique characters")
    print(f"Password Length:       {length} characters")
    print(f"Logarithmic Entropy: {entropy} bits")
    print(f"Estimated Strength:  {strength}")
    print(colored("-----------------------------", Colors.BOLD) + "\n")

    generated_passwords = []
    
    for i in range(1, count + 1):
        pwd = generate_password(length)
        generated_passwords.append(pwd)
        print(f"#{i}: {colored(pwd, Colors.INFO)}") # Colorize the actual generated password
        
    # 4. Save to Temporary File and Encrypt (if requested)
    if temp_file and save_file:
        try:
            # 4a: Write to Temporary File
            with open(temp_file, 'a', encoding='utf-8') as f:
                for pwd in generated_passwords:
                    f.write(f"{pwd}\n")
                f.write("\n--- End of Passwords ---\n")
            
            print(colored(f"\nSuccessfully saved {count} passwords to temporary file '{temp_file}'.", Colors.INFO))
            
            # 4b: Get Password from User
            encryption_key = getpass.getpass("Enter your chosen encryption password (will not be displayed): ").strip()
            if not encryption_key:
                print(colored("Error: Encryption password cannot be empty. Cancelling save.", Colors.FAIL))
                raise ValueError("Empty encryption key.")

            # 4c: Encrypt
            encrypt_file(temp_file, save_file, encryption_key)
            
            # 4d: Clean up the Temporary File
            secure_delete(temp_file)
            
        except (ValueError, IOError) as e:
            print(colored(f"\nError during save/encryption process: {e}", Colors.FAIL))
            if os.path.exists(temp_file):
                print(colored(f"The temporary file '{temp_file}' still exists and must be SECURELY DELETED.", Colors.FAIL + Colors.BOLD))
        except Exception as e:
            print(colored(f"\nAn unexpected error occurred: {e}", Colors.FAIL))
            if os.path.exists(temp_file):
                print(colored(f"The temporary file '{temp_file}' still exists and must be SECURELY DELETED.", Colors.FAIL + Colors.BOLD))
            
    print("\nGenerator finished. Don't forget to secure the generated passwords.")

# ---------------------------------------------------------------------

def decrypt_file():
    """Logic for decrypting an encrypted file and offering re-encryption."""
    print(colored("\n--- Fernet File Decryption ---", Colors.HEADER + Colors.BOLD))
    
    encrypted_file = input("Enter the name of the ENCRYPTED file (e.g., passwords_encrypted_YYYYMMDD_HHMMSS.enc): ").strip()
    
    if not encrypted_file or not os.path.exists(encrypted_file):
        print(colored(f"Decryption cancelled. File '{encrypted_file}' not found or name not provided.", Colors.WARNING))
        return

    if encrypted_file.endswith(".enc"):
        decrypted_file = encrypted_file[:-4] + "_decrypted.txt"
    else:
        decrypted_file = encrypted_file + "_decrypted.txt"
    
    print(colored(f"The decrypted content will be saved to: {decrypted_file}", Colors.INFO))
    
    decryption_key = getpass.getpass("Enter the decryption password (will not be displayed): ").strip()

    if not decryption_key:
        print(colored("Error: Decryption password cannot be empty. Cancelling decryption.", Colors.FAIL))
        return

    try:
        # 1. Read encrypted content (binary mode)
        with open(encrypted_file, 'rb') as f_in_binary:
            file_content = f_in_binary.read()
        
        # 2. Extract salt (first 16 bytes) and encrypted token
        if len(file_content) < 16:
            print(colored("Error: Encrypted file is too short/corrupted.", Colors.FAIL))
            return

        salt = file_content[:16]
        encrypted_token = file_content[16:]
        
        # 3. Derive key and initialize Fernet
        key = derive_key(decryption_key, salt)
        f = Fernet(key)

        # 4. Decrypt the content
        try:
            decrypted_bytes = f.decrypt(encrypted_token)
        except InvalidToken:
            print(colored("\n❌ Decryption failed: Invalid password or corrupted data.", Colors.FAIL))
            return

        # 5. Decode to text (assuming it's UTF-8 text)
        decrypted_content = decrypted_bytes.decode('utf-8')

        # 6. Write decrypted content to temporary file (text mode)
        with open(decrypted_file, 'w', encoding='utf-8') as f_out_text:
            f_out_text.write(decrypted_content)

        print(colored(f"\nDecryption successful! Content saved to '{decrypted_file}'.", Colors.SUCCESS))

        # --- Display Content ---
        print(colored("\n--- Decrypted Content ---", Colors.BOLD))
        print(decrypted_content)
        print(colored("---------------------------", Colors.BOLD) + "\n")

        print(colored("WARNING: The file listed above is currently saved as PLAIN TEXT on disk.", Colors.FAIL))
        print("You can now open and edit the file if needed.")

        # --- External Editor Launch Option ---
        default_editor = ""
        current_os = platform.system()
        
        if current_os == 'Linux':
            default_editor = 'nano'
        elif current_os == 'Darwin': # macOS
            default_editor = 'open' # Opens with default app
        elif current_os == 'Windows':
            default_editor = 'notepad'
        
        editor_prompt = f"To edit the plain-text file, enter an editor command (e.g., '{default_editor}', 'vi', 'code'). Leave blank to skip: "
        editor_choice = input(editor_prompt).strip()

        if editor_choice:
            try:
                # Use subprocess to run the editor command on the file
                print(colored(f"Launching editor: {editor_choice} {decrypted_file}", Colors.INFO))
                
                # Check for common non-blocking commands (like 'open' on Mac or 'start' on Windows - though 'start' requires shell=True)
                # Sticking to simple run for cross-platform compatibility, which will block for CLI editors.
                subprocess.run([editor_choice, decrypted_file])
                
                # We need to re-read the file after the user (hopefully) edited and saved it
                print(colored(f"Editor closed. Re-reading file '{decrypted_file}' for re-encryption...", Colors.INFO))

            except FileNotFoundError:
                print(colored(f"❌ Error: Editor command '{editor_choice}' not found.", Colors.FAIL))
            except Exception as e:
                print(colored(f"❌ Error launching editor: {e}", Colors.FAIL))
        
        # --- Offer Re-encryption ---
        re_encrypt_choice = input(f"Do you want to re-encrypt '{decrypted_file}' now? (y/n): ").strip().lower()
        
        if re_encrypt_choice == 'y':
            print(f"Re-encrypting the file back to '{encrypted_file}'.")
            
            # Re-encrypt using the original password
            encrypt_file(decrypted_file, encrypted_file, decryption_key)
            
            # Clean up the decrypted file SECURELY
            secure_delete(decrypted_file) 
            print(colored("\nRe-encryption complete. Plain-text file automatically deleted.", Colors.SUCCESS))
            
        else:
            print(colored(f"\nWARNING: The file '{decrypted_file}' is currently in PLAIN TEXT.", Colors.FAIL + Colors.BOLD))
            print("Remember to SECURELY delete or re-encrypt it when finished editing.")


    except IOError as e:
        print(colored(f"\nError: Could not read/write file during decryption: {e}", Colors.FAIL))
        if os.path.exists(decrypted_file):
            # Clean up the failed output file 
            secure_delete(decrypted_file)
            print(f"Incomplete output file has been deleted.")
            
    except Exception as e:
        print(colored(f"\nAn unexpected error occurred: {e}", Colors.FAIL))
        if os.path.exists(decrypted_file):
            # Clean up the failed output file 
            secure_delete(decrypted_file)
            print(f"Incomplete output file has been deleted.")

# ---------------------------------------------------------------------

def main():
    """Main execution function with choice of Generate or Decrypt."""
    
    print(colored("--- Unicode Password Utility (Generate/Decrypt) ---", Colors.HEADER + Colors.BOLD))
    
    choice = input("Do you want to (G)enerate passwords or (D)ecrypt a file? (g/d): ").strip().lower()
    
    if choice == 'g':
        run_generator()
    elif choice == 'd':
        decrypt_file()
    else:
        print(colored("Invalid choice. Exiting.", Colors.WARNING))
        
    print("\nHave a great day!")


if __name__ == "__main__":
    main()



if __name__ == "__main__":
    main()
