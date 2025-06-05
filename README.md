# Integrated Compression-Encryption System (ICES)  

## Overview  
This repository contains the source code and benchmarking tools for the **Integrated Compression-Encryption System (ICES)**, a modular Python framework designed to optimize file storage efficiency while ensuring robust encryption. The system integrates **DEFLATE compression** with **AES-256 encryption** to achieve a balance between performance and security.

## Features  
- **Lossless compression** using DEFLATE for efficient storage.  
- **AES-256 encryption** for secure data protection.  
- **Benchmarking support** to analyze performance metrics such as compression ratio, speed, and memory usage.  
- **Chunked I/O processing** for handling large files efficiently.  
- **Cross-platform compatibility** tested on Windows and Linux.  

## Repository Structure  
- **`compress_encrypt.py`** – Core script for compressing and encrypting files.  
- **`decrypt_decompress.py`** – Script for decrypting and decompressing files.  
- **`benchmark_tool.py`** – Tool for benchmarking compression and encryption performance.  
- **`create_test_files.ps1`** – PowerShell script for generating test datasets.  
- **`benchmark_results.csv`** – Raw benchmark data collected from tests.  

## Installation  
To run the system, install the necessary dependencies using **pip**:

```bash
pip install cryptography psutil
```

Ensure you have Python **3.8+** installed.

## Usage  

### Compression & Encryption  
To compress and encrypt a file or folder:  
```bash
python compress_encrypt.py
```

### Decryption & Decompression  
To decrypt and decompress a file:  
```bash
python decrypt_decompress.py
```

### Running Benchmarks  
Execute the benchmark tool to analyze performance across various datasets:  
```bash
python benchmark_tool.py
```

## Security Notes  
- **Ensure strong passwords** when encrypting files.  
- **Avoid sharing passwords** used for encryption.  
- **Use secure storage** for encrypted outputs to prevent unauthorized access.  
