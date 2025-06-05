"""
COMPRESS_ENCRYPT.PY - Secure File Compression and Encryption Tool
================================================================

Usage:
------
1. Interactive Mode:
   $ python compress_encrypt.py
   - Follow prompts for input path, output file, algorithm, and password

2. Command-line Mode:
   $ python compress_encrypt.py --input <path> --output <file> --algorithm <AES|XOR> --password <password>

Features:
---------
- AES-256-CBC and XOR encryption options
- ZIP compression with DEFLATE algorithm
- PBKDF2 key derivation with 600,000 iterations
- Secure password confirmation
- Automatic temporary file cleanup
- Progress tracking for large files
- Cross-platform compatibility
"""

import os
import sys
import argparse
import zipfile
import hashlib
import secrets
import signal
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Configuration
BUFFER_SIZE = 64 * 1024 * 1024  # 64MB buffer for large files
PBKDF2_ITERATIONS = 600000       # NIST-recommended iteration count
TEMP_EXT = ".tmp.zip"            # Temporary zip extension
temp_files = []                  # Global cleanup list

def signal_handler(sig, frame):
    """
    Handle interrupt signals (Ctrl+C)
    Inputs:  sig - signal number
             frame - current stack frame
    Outputs: Clean exit with file cleanup
    """
    print("\n🛑 Operation cancelled by user!")
    cleanup()
    sys.exit(1)

def cleanup():
    """Remove temporary files from all processing stages"""
    for f in temp_files:
        if os.path.exists(f):
            os.remove(f)

def validate_input_path(path):
    """
    Validate input path exists and is readable
    Inputs:  path - filesystem path to validate
    Returns: Absolute validated path
    Raises:  FileNotFoundError, PermissionError
    """
    abs_path = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"Path '{abs_path}' not found")
    if not os.access(abs_path, os.R_OK):
        raise PermissionError(f"No read access to '{abs_path}'")
    return abs_path

def compress(input_path, zip_path):
    """
    Create encrypted zip archive with progress tracking
    Inputs:  input_path - File/directory to compress
             zip_path - Output zip file path
    Returns: Path to created zip file
    Raises:  RuntimeError on compression failure
    """
    try:
        total_files = 0
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if os.path.isdir(input_path):
                # Recursive directory compression
                for root, _, files in os.walk(input_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        arcname = os.path.relpath(full_path, input_path)
                        zipf.write(full_path, arcname)
                        total_files += 1
                        print(f"\r📦 Compressed {total_files} files...", end="")
            else:
                # Single file compression
                zipf.write(input_path, os.path.basename(input_path))
                total_files = 1

        print(f"\n✅ Compression complete: {total_files} files processed")
        return zip_path

    except Exception as e:
        cleanup()
        raise RuntimeError(f"Compression failed: {str(e)}") from e

def derive_key(password, salt):
    """
    Generate encryption key from password using PBKDF2
    Inputs:  password - User-provided string
             salt - 16-byte random value
    Returns: 32-byte encryption key
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32
    )

def encrypt_file(input_path, output_path, algorithm, password):
    """
    Core encryption routine with algorithm selection
    Inputs:  input_path - File to encrypt
             output_path - Destination path
             algorithm - 'AES' or 'XOR'
             password - Encryption password
    Raises:  KeyboardInterrupt on user cancellation
    """
    try:
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        bytes_processed = 0

        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            fout.write(salt)  # Always write salt first

            if algorithm == "AES":
                # AES-256-CBC Implementation
                iv = secrets.token_bytes(16)
                fout.write(iv)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padder = padding.PKCS7(128).padder()

                # Chunked encryption
                while chunk := fin.read(BUFFER_SIZE):
                    padded = padder.update(chunk)
                    fout.write(encryptor.update(padded))
                    bytes_processed += len(chunk)
                    print(f"\r🔒 Encrypted {bytes_processed/1024/1024:.1f} MB...", end="")

                # Finalize padding and encryption
                final_padded = padder.finalize()
                encrypted_final = encryptor.update(final_padded) + encryptor.finalize()
                fout.write(encrypted_final)

            else:  # XOR Encryption
                fout.write(b'XOR')  # Algorithm marker
                while chunk := fin.read(BUFFER_SIZE):
                    encrypted = bytes(b ^ key[i % 32] for i, b in enumerate(chunk))
                    fout.write(encrypted)
                    bytes_processed += len(chunk)
                    print(f"\r🔒 Encrypted {bytes_processed/1024/1024:.1f} MB...", end="")

        print("\n✅ Encryption successful")

    except KeyboardInterrupt:
        cleanup()
        raise

def main():
    """
    Main program workflow controller
    Handles user interaction and process coordination
    """
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--input', help='Input file/directory path')
    parser.add_argument('--output', help='Output encrypted file path')
    parser.add_argument('--algorithm', choices=['AES', 'XOR'], help='Encryption algorithm')
    parser.add_argument('--password', help='Encryption password')

    try:
        args = parser.parse_args()

        # Interactive Mode
        if not args.input:
            print("\n🔐 Secure File Compression & Encryption")
            args.input = validate_input_path(input("📂 Enter path to encrypt: ").strip())
            default_output = f"{args.input}.bin"
            args.output = input(f"📂 Output path [{default_output}]: ").strip() or default_output
            args.algorithm = input("⚙️  Encryption algorithm [AES/XOR] (default AES): ").upper() or "AES"

            # Password validation loop
            while True:
                args.password = getpass("🔑 Enter password (min 8 characters): ")
                confirm = getpass("🔑 Confirm password: ")

                if len(args.password) < 8:
                    print("❌ Password must be at least 8 characters!")
                    continue
                if args.password != confirm:
                    print("❌ Passwords do not match!")
                    continue
                break

        # Non-interactive validation
        if len(args.password) < 8:
            raise ValueError("Password must be at least 8 characters")

        # Path processing
        input_path = validate_input_path(args.input)
        output_path = os.path.abspath(args.output)
        temp_zip = output_path + TEMP_EXT
        temp_files.append(temp_zip)

        # Execute workflow
        print("\n🚀 Starting processing...")
        compress(input_path, temp_zip)
        encrypt_file(temp_zip, output_path, args.algorithm, args.password)
        cleanup()
        print(f"\n🎉 Success! Encrypted file: {output_path}")

    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()