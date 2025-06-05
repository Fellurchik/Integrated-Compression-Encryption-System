"""
BENCHMARK_TOOL.PY - Performance Testing for Compression and Encryption Algorithms
=================================================================================

Usage:
------
$ python benchmark_tool.py

Features:
---------
- Tests DEFLATE and LZMA compression algorithms
- Benchmarks AES and XOR encryption performance
- Measures throughput, memory usage, and compression ratios
- Supports both files and directories as input
- Automatic test data cleanup
- CSV results export
- Resource monitoring (execution time, memory footprint)
"""

import os
import time
import csv
import psutil
import uuid
from zipfile import ZipFile, ZIP_DEFLATED, ZIP_LZMA
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Test configuration
TEST_DIR = r"C:\ThesisTests"  # Root directory for test files
RESULTS_FILE = r"C:\ThesisTests\benchmark_results.csv"  # Results output path
BUFFER_SIZE = 64 * 1024 * 1024  # 64MB chunks for file operations


def get_mem_usage():
    """
    Get current process memory usage
    Returns: RSS memory usage in bytes
    """
    return psutil.Process().memory_info().rss


def xor_crypt(data, key):
    """
    Simple XOR encryption/decryption
    Inputs:  data - Bytes to process
             key - Encryption key
    Returns: XOR-processed bytes
    """
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def test_compression(input_path, method):
    """
    Measure compression performance metrics
    Inputs:  input_path - File/directory to compress
             method - ZIP_DEFLATED or ZIP_LZMA
    Returns: Dictionary with performance metrics
    Raises:  Propagates file operation exceptions
    """
    temp_name = f"temp_{uuid.uuid4().hex}.zip"
    output = os.path.join(TEST_DIR, temp_name)
    start_time = time.perf_counter()
    mem_before = get_mem_usage()

    try:
        # Create compressed archive
        with ZipFile(output, 'w', method) as zipf:
            if os.path.isdir(input_path):
                # Recursive directory compression
                for root, _, files in os.walk(input_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        zipf.write(full_path, os.path.relpath(full_path, input_path))
            else:
                # Single file compression
                zipf.write(input_path, os.path.basename(input_path))

        # Calculate compression ratio
        comp_size = os.path.getsize(output)
        orig_size = os.path.getsize(input_path) if os.path.isfile(input_path) else sum(
            os.path.getsize(os.path.join(dirpath, filename))
            for dirpath, _, filenames in os.walk(input_path)
            for filename in filenames
        )
        comp_ratio = (1 - (comp_size / orig_size)) * 100
    except Exception as e:
        if os.path.exists(output):
            os.remove(output)
        raise e

    return {
        'output': output,
        'time': time.perf_counter() - start_time,
        'mem_used': (get_mem_usage() - mem_before) / 1024 / 1024,
        'ratio': comp_ratio
    }


def test_encryption(input_file, method, key):
    """
    Measure encryption performance metrics
    Inputs:  input_file - File to encrypt
             method - 'AES' or 'XOR'
             key - Encryption key
    Returns: Dictionary with performance metrics
    Raises:  FileNotFoundError, encryption-related exceptions
    """
    # Prepare crypto parameters
    iv = os.urandom(16) if method == 'AES' else b''
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) if method == 'AES' else None
    temp_name = f"encrypted_{uuid.uuid4().hex}.bin"
    output = os.path.join(TEST_DIR, temp_name)

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    start_time = time.perf_counter()
    mem_before = get_mem_usage()

    try:
        # Read entire file into memory for processing
        with open(input_file, 'rb') as fin:
            plaintext = fin.read()

        # AES encryption with PKCS7 padding
        if method == 'AES':
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            with open(output, 'wb') as fout:
                fout.write(iv)
                fout.write(ciphertext)
        # XOR encryption
        else:
            with open(output, 'wb') as fout:
                fout.write(xor_crypt(plaintext, key))

        # Calculate throughput (MB/s)
        throughput = os.path.getsize(input_file) / (time.perf_counter() - start_time)
    finally:
        # Clean up encrypted file
        if os.path.exists(output):
            os.remove(output)

    return {
        'time': time.perf_counter() - start_time,
        'mem_used': (get_mem_usage() - mem_before) / 1024 / 1024,
        'throughput': throughput / 1024 / 1024
    }


def run_benchmarks():
    """
    Execute benchmark test suite
    Returns: List of test result dictionaries
    """
    # Test case configuration: (file_path, category_name)
    test_cases = [
        ('Text/10gb.txt', 'Text'),
        ('Images', 'Images'),
        ('Logs/binary.log', 'Logs'),
        ('Medical', 'Medical'),
        ('Financial/transactions.csv', 'Financial')
    ]

    results = []

    for file_path, category in test_cases:
        full_path = os.path.join(TEST_DIR, file_path)
        print(f"\n=== Testing {category} ({os.path.basename(file_path)}) ===")

        try:
            # Compression tests
            deflate = test_compression(full_path, ZIP_DEFLATED)
            lzma = test_compression(full_path, ZIP_LZMA)

            # Encryption tests (using DEFLATE compressed output)
            key = os.urandom(32)
            aes = test_encryption(deflate['output'], 'AES', key)
            xor = test_encryption(deflate['output'], 'XOR', key)

            # Collect metrics
            results.append({
                'category': category,
                'original_size': os.path.getsize(full_path) if os.path.isfile(full_path) else "Directory",
                'deflate_ratio': deflate['ratio'],
                'deflate_time': deflate['time'],
                'lzma_ratio': lzma['ratio'],
                'lzma_time': lzma['time'],
                'aes_throughput': aes['throughput'],
                'xor_throughput': xor['throughput'],
                'max_mem': max(deflate['mem_used'], lzma['mem_used'], aes['mem_used'])
            })

        finally:
            # Cleanup temporary files
            if 'deflate' in locals() and os.path.exists(deflate['output']):
                os.remove(deflate['output'])
            if 'lzma' in locals() and os.path.exists(lzma['output']):
                os.remove(lzma['output'])

    return results


def save_results(data):
    """
    Save benchmark results to CSV file
    Inputs:  data - List of result dictionaries
    Outputs: Creates/overwrites RESULTS_FILE
    """
    with open(RESULTS_FILE, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    print(f"\nResults saved to {RESULTS_FILE}")


if __name__ == "__main__":
    # System information header
    print(f"Starting benchmarks")
    print(f"System RAM: {psutil.virtual_memory().total / 1024 / 1024 / 1024:.1f} GB")

    # Execute benchmarks and save
    results = run_benchmarks()
    save_results(results)