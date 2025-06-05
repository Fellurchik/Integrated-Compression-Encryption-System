"""
DECRYPT_DECOMPRESS.PY - Secure File Decryption and Extraction Tool
=================================================================

Usage:
------
1. Interactive Mode:
   $ python decrypt_decompress.py
   - Follow the prompts to enter encrypted file, output directory, and password

2. Command-line Mode:
   $ python decrypt_decompress.py --input <encrypted_file> --output <directory> --password <password>

Features:
---------
- AES-256-CBC and XOR encryption support
- PBKDF2 key derivation with 600,000 iterations
- Secure password handling with getpass
- Graceful interrupt handling (Ctrl+C)
- Automatic cleanup of temporary files
- Detailed progress reporting
- Cross-platform compatibility
"""

import os
import sys
import argparse
import zipfile
import hashlib
import signal
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Configuration constants
BUFFER_SIZE = 64 * 1024 * 1024  # 64MB buffer for large file handling
PBKDF2_ITERATIONS = 600000  # NIST-recommended iteration count
TEMP_EXT = ".tmp.zip"  # Temporary zip file extension
temp_files = []  # Global list for cleanup tracking


def signal_handler(sig, frame):
    """
    Handle interrupt signals (Ctrl+C) gracefully
    Inputs:  sig - signal number
             frame - current stack frame
    Outputs: Terminates program with cleanup
    """
    print("\n🛑 Operation cancelled by user!")
    cleanup()
    sys.exit(1)


def cleanup():
    """
    Remove temporary files created during processing
    Inputs: None
    Outputs: Deletes files listed in temp_files
    """
    for f in temp_files:
        if os.path.exists(f):
            os.remove(f)


def validate_encrypted_file(path):
    """
    Verify encrypted file meets minimum requirements
    Inputs:  path - file path to validate
    Returns: Absolute validated file path
    Raises:  FileNotFoundError, ValueError, PermissionError
    """
    abs_path = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File '{abs_path}' not found")
    if os.path.getsize(abs_path) < 32:
        raise ValueError("Invalid encrypted file (too small)")
    if not os.access(abs_path, os.R_OK):
        raise PermissionError(f"No read access to '{abs_path}'")
    return abs_path


def derive_key(password, salt):
    """
    Derive cryptographic key from password using PBKDF2-HMAC-SHA256
    Inputs:  password - User-provided string
             salt - 16-byte random value from encrypted file
    Returns: 32-byte derived key
    Raises: ValueError on empty password (shouldn't occur with earlier validation)
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32
    )


def decrypt_file(input_path, password):
    """
    Core decryption routine with progress reporting
    Inputs:  input_path - Path to encrypted file
             password - User-provided decryption password
    Returns: Path to temporary decrypted zip file
    Raises:  RuntimeError on decryption failure
    """
    temp_zip = input_path + TEMP_EXT
    temp_files.append(temp_zip)

    try:
        with open(input_path, 'rb') as fin, open(temp_zip, 'wb') as fout:
            salt = fin.read(16)
            key = derive_key(password, salt)
            algorithm_marker = fin.read(3)
            bytes_processed = 0

            # XOR Encryption Path
            if algorithm_marker == b'XOR':
                while chunk := fin.read(BUFFER_SIZE):
                    decrypted = bytes(b ^ key[i % 32] for i, b in enumerate(chunk))
                    fout.write(decrypted)
                    bytes_processed += len(chunk)
                    print(f"\r🔓 Decrypted {bytes_processed / 1024 / 1024:.1f} MB...", end="")

            # AES-256-CBC Encryption Path
            else:
                iv = algorithm_marker + fin.read(13)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                unpadder = padding.PKCS7(128).unpadder()

                while chunk := fin.read(BUFFER_SIZE):
                    decrypted = unpadder.update(decryptor.update(chunk))
                    fout.write(decrypted)
                    bytes_processed += len(chunk)
                    print(f"\r🔓 Decrypted {bytes_processed / 1024 / 1024:.1f} MB...", end="")

                # Finalize decryption and unpadding
                final = unpadder.finalize() + decryptor.finalize()
                fout.write(final)

        print("\n✅ Decryption successful")
        return temp_zip

    except (padding.InvalidUnpadding, ValueError) as e:
        cleanup()
        raise RuntimeError("Incorrect password or corrupted file") from e
    except KeyboardInterrupt:
        cleanup()
        raise


def decompress(zip_path, output_dir):
    """
    Extract ZIP contents with validation and progress tracking
    Inputs:  zip_path - Path to decrypted zip file
             output_dir - Target extraction directory
    Returns: Number of extracted files
    Raises:  RuntimeError on invalid ZIP format
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        extracted_count = 0

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for file in zip_ref.infolist():
                zip_ref.extract(file, output_dir)
                extracted_count += 1
                print(f"\r📂 Extracted {extracted_count} files...", end="")

        print(f"\n✅ Extraction complete to: {output_dir}")
        return extracted_count

    except zipfile.BadZipFile as e:
        cleanup()
        raise RuntimeError("Corrupted ZIP file - possible password error") from e


def main():
    """
    Main program execution flow
    Handles argument parsing and workflow coordination
    """
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--input', help='Encrypted input file path')
    parser.add_argument('--output', help='Output directory path')
    parser.add_argument('--password', help='Decryption password')

    try:
        args = parser.parse_args()

        # Interactive Mode
        if not args.input:
            print("\n🔓 Secure File Decryption & Extraction")
            args.input = validate_encrypted_file(input("📂 Enter encrypted file: ").strip())
            default_output = f"{args.input}_decrypted"
            args.output = input(f"📂 Output directory [{default_output}]: ").strip() or default_output
            args.password = getpass("🔑 Enter password: ")

        # Validate inputs
        input_path = validate_encrypted_file(args.input)
        output_dir = os.path.abspath(args.output)

        # Execute workflow
        print("\n🚀 Starting decryption...")
        temp_zip = decrypt_file(input_path, args.password)

        print("\n🚀 Starting extraction...")
        file_count = decompress(temp_zip, output_dir)

        cleanup()
        print(f"\n🎉 Success! {file_count} files restored to: {output_dir}")

    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()