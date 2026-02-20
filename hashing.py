#!/usr/bin/env python3
"""
File Integrity Checker - Step 2: Hash Calculation + Storage
This script calculates SHA-256 hashes of files and stores them for comparison.
"""


import hashlib
import sys
import json
import os
from datetime import datetime
from tkinter.ttk import Style



def calculate_hash(filepath):
    """
    Calculate SHA-256 hash of a file.
    
    Args:
        filepath: Path to the file to hash
        
    Returns:
        Hexadecimal string representation of the hash
    """
    # Create a new SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    try:
        # Open the file in binary read mode
        with open(filepath, "rb") as f:
            # Read the file in chunks (useful for large files)
            # 4096 bytes = 4KB at a time
            for byte_block in iter(lambda: f.read(4096), b""):
                # Update the hash with each chunk
                sha256_hash.update(byte_block)
        
        # Return the hexadecimal representation of the hash
        return sha256_hash.hexdigest()
    
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found.")
        return None
    except PermissionError:
        print(f"Error: Permission denied to read '{filepath}'.")
        return None
    except Exception as e:
        print(f"Error reading file: {e}")
        return None


# File to store our hashes (like a database)
HASH_STORAGE_FILE = "integrity_hashes.json"


def load_hashes():
    """
    Load stored hashes from the JSON file.
    
    Returns:
        Dictionary with filepath as key and hash info as value
        If file doesn't exist, returns empty dictionary
    """
    # Check if the storage file exists
    if not os.path.exists(HASH_STORAGE_FILE):
        return {}  # Return empty dictionary if no storage file yet
    
    try:
        # Open and read the JSON file
        with open(HASH_STORAGE_FILE, "r") as f:
            return json.load(f)  # Convert JSON text back to Python dictionary
    except Exception as e:
        print(f"Error loading hashes: {e}")
        return {}


def save_hashes(hash_data):
    """
    Save hashes to the JSON file.
    
    Args:
        hash_data: Dictionary of filepath -> hash information
    """
    try:
        # Open file for writing (creates it if doesn't exist)
        with open(HASH_STORAGE_FILE, "w") as f:
            # Convert Python dictionary to JSON and write it
            # indent=2 makes it pretty and readable
            json.dump(hash_data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving hashes: {e}")
        return False


def store_file_hash(filepath):
    """
    Calculate hash of a file and store it.
    
    Args:
        filepath: Path to the file to hash and store
    """
    # Calculate the hash
    file_hash = calculate_hash(filepath)
    if not file_hash:
        return False
    
    # Get file size for additional info
    file_size = os.path.getsize(filepath)
    
    # Load existing hashes
    all_hashes = load_hashes()
    
    # Store this file's information
    all_hashes[filepath] = {
        "hash": file_hash,
        "timestamp": datetime.now().isoformat(),  # When we stored it
        "size": file_size  # File size in bytes
    }
    
    # Save back to file
    if save_hashes(all_hashes):
        print(f"✓ Hash stored for: {filepath}")
        print(f"  Hash: {file_hash}")
        return True
    return False


def check_file_integrity(filepath):
    """
    Check if a file has been modified by comparing its current hash
    to the stored hash.
    
    Args:
        filepath: Path to the file to check
    """
    # Calculate current hash
    current_hash = calculate_hash(filepath)
    if not current_hash:
        return
    
    # Load stored hashes
    all_hashes = load_hashes()
    
    # Check if we have a stored hash for this file
    if filepath not in all_hashes:
        print(f"⚠ No stored hash found for: {filepath}")
        print(f"  Run 'init' or 'update' command first to initialize this file.")
        return
    
    # Get the stored hash
    stored_info = all_hashes[filepath]
    stored_hash = stored_info["hash"]
    

    # Compare hashes
    if current_hash == stored_hash:
        print(f"✓ Status: Unmodified")
        print(f"  File: {filepath}")
        print(f"  Hash: {current_hash}")
    else:
        print(f"⚠ Status: Modified ")
        print(f"  File: {filepath}")
        print(f"  Stored hash:  {stored_hash}")
        print(f"  Current hash: {current_hash}")
        print(f"  Last verified: {stored_info['timestamp']}")


def update_file_hash(filepath):
    """
    Update the stored hash for a file (use this to accept legitimate changes).
    
    Args:
        filepath: Path to the file to update
    """
    # Calculate the new hash
    file_hash = calculate_hash(filepath)
    if not file_hash:
        return False
    
    # Get file size
    file_size = os.path.getsize(filepath)
    
    # Load existing hashes
    all_hashes = load_hashes()
    
    # Update this file's information
    all_hashes[filepath] = {
        "hash": file_hash,
        "timestamp": datetime.now().isoformat(),
        "size": file_size
    }
    
    # Save back to file
    if save_hashes(all_hashes):
        print(f"✓ Hash updated successfully.")
        print(f"  File: {filepath}")
        print(f"  New hash: {file_hash}")
        return True
    return False


def init_directory(path):
    """
    Initialize hashes for all files in a directory (or single file).
    
    Args:
        path: Directory path or single file path
    """
    files_to_process = []
    
    # Check if path is a directory or a file
    if os.path.isfile(path):
        # Single file
        files_to_process.append(path)
    elif os.path.isdir(path):
        # Directory - get all files (not subdirectories)
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isfile(full_path):
                files_to_process.append(full_path)
    else:
        print(f"Error: '{path}' is not a valid file or directory")
        return
    
    if not files_to_process:
        print(f"No files found in '{path}'")
        return
    
    # Load existing hashes
    all_hashes = load_hashes()
    
    print(f"Initializing integrity hashes for {len(files_to_process)} file(s)...")
    print()
    
    # Process each file
    success_count = 0
    for filepath in files_to_process:
        file_hash = calculate_hash(filepath)
        if file_hash:
            file_size = os.path.getsize(filepath)
            all_hashes[filepath] = {
                "hash": file_hash,
                "timestamp": datetime.now().isoformat(),
                "size": file_size
            }
            print(f"  ✓ {filepath}")
            success_count += 1
        else:
            print(f"  ✗ {filepath} (failed)")
    
    # Save all hashes
    if save_hashes(all_hashes):
        print()
        print(f"✓ Hashes stored successfully.")
        print(f"  {success_count}/{len(files_to_process)} files initialized")
    else:
        print("Error: Failed to save hashes")


# Main program
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("File Integrity Checker")
        print("=" * 50)
        print("\nUsage:")
        print("  python3 integrity_check.py init <path>")
        print("    Initialize hashes for file(s) in a directory or single file")
        print()
        print("  python3 integrity_check.py check <filepath>")
        print("    Check if a file has been modified")
        print()
        print("  python3 integrity_check.py update <filepath>")
        print("    Update stored hash (accept legitimate changes)")
        print()
        print("Examples:")
        print("  python3 integrity_check.py init /var/log")
        print("  python3 integrity_check.py init test_log.txt")
        print("  python3 integrity_check.py check test_log.txt")
        print("  python3 integrity_check.py update test_log.txt")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    path = sys.argv[2]
    
    if command == "init":
        init_directory(path)
    elif command == "check":
        check_file_integrity(path)
    elif command == "update":
        update_file_hash(path)
    else:
        print(f"Error: Unknown command '{command}'")
        print("Valid commands: init, check, update")
        sys.exit(1)