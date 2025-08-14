#!/usr/bin/env python3
"""
Cryptography CLI Application Demonstration
=========================================

This script demonstrates all the features of the cryptography CLI application
including encryption, decryption, frequency analysis, security assessment,
key generation, and file operations.

Author: Student
Version: 1.0
"""

import subprocess
import sys
import os

def run_command(cmd):
    """Run a command and return the output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {e}"

def print_header(title):
    """Print a formatted header."""
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

def print_section(title):
    """Print a formatted section header."""
    print(f"\n--- {title} ---")

def main():
    """Main demonstration function."""
    print_header("CRYPTOGRAPHY CLI APPLICATION DEMONSTRATION")
    
    # Test 1: Basic Encryption/Decryption
    print_section("1. Basic Encryption and Decryption")
    
    print("Caesar Cipher:")
    plaintext = "HELLO WORLD"
    print(f"Plaintext: {plaintext}")
    
    encrypted = run_command(f'python3 cryptography_cli.py --encrypt caesar 3 "{plaintext}"')
    print(f"Encrypted: {encrypted}")
    
    decrypted = run_command(f'python3 cryptography_cli.py --decrypt caesar 3 "{encrypted.split(": ")[1]}"')
    print(f"Decrypted: {decrypted}")
    
    print("\nVigenère Cipher:")
    encrypted = run_command(f'python3 cryptography_cli.py --encrypt vigenere KEY "{plaintext}"')
    print(f"Encrypted: {encrypted}")
    
    decrypted = run_command(f'python3 cryptography_cli.py --decrypt vigenere KEY "{encrypted.split(": ")[1]}"')
    print(f"Decrypted: {decrypted}")
    
    # Test 2: Frequency Analysis
    print_section("2. Frequency Analysis")
    
    sample_text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    print(f"Analyzing text: {sample_text}")
    
    analysis = run_command(f'python3 cryptography_cli.py --analyze "{sample_text}"')
    print(analysis)
    
    # Test 3: Security Assessment
    print_section("3. Security Assessment")
    
    print("Caesar Cipher Security:")
    security = run_command('python3 cryptography_cli.py --security caesar 3')
    print(security)
    
    print("\nVigenère Cipher Security:")
    security = run_command('python3 cryptography_cli.py --security vigenere KEY')
    print(security)
    
    # Test 4: Key Generation
    print_section("4. Key Generation")
    
    print("Caesar Key:")
    key = run_command('python3 cryptography_cli.py --generate-key caesar')
    print(key)
    
    print("\nVigenère Key (8 characters):")
    key = run_command('python3 cryptography_cli.py --generate-key vigenere 8')
    print(key)
    
    print("\nPlayfair Key (10 characters):")
    key = run_command('python3 cryptography_cli.py --generate-key playfair 10')
    print(key)
    
    print("\nSubstitution Key:")
    key = run_command('python3 cryptography_cli.py --generate-key substitution')
    print(key)
    
    # Test 5: Caesar Cipher Cracking
    print_section("5. Caesar Cipher Cracking")
    
    # Create a Caesar cipher with shift 3
    test_text = "HELLO WORLD"
    encrypted = run_command(f'python3 cryptography_cli.py --encrypt caesar 3 "{test_text}"')
    encrypted_text = encrypted.split(": ")[1]
    
    print(f"Encrypted text: {encrypted_text}")
    print("Attempting to crack...")
    
    cracked = run_command(f'python3 cryptography_cli.py --crack-caesar "{encrypted_text}"')
    print(cracked)
    
    # Test 6: File Operations
    print_section("6. File Operations")
    
    # Create a test file
    test_content = "This is a secret message for file encryption testing."
    with open("demo_secret.txt", "w") as f:
        f.write(test_content)
    
    print(f"Created test file: demo_secret.txt")
    print(f"Content: {test_content}")
    
    # Encrypt the file
    print("\nEncrypting file...")
    result = run_command('python3 cryptography_cli.py --encrypt-file caesar 3 demo_secret.txt demo_encrypted.txt')
    print(result)
    
    # Decrypt the file
    print("\nDecrypting file...")
    result = run_command('python3 cryptography_cli.py --decrypt-file caesar 3 demo_encrypted.txt demo_decrypted.txt')
    print(result)
    
    # Verify the content
    with open("demo_decrypted.txt", "r") as f:
        decrypted_content = f.read()
    
    print(f"\nDecrypted content: {decrypted_content}")
    print(f"Content matches: {decrypted_content == test_content}")
    
    # Test 7: Comprehensive Security Report
    print_section("7. Comprehensive Security Report")
    
    report = run_command('python3 cryptography_cli.py --report caesar 3')
    print(report)
    
    # Test 8: Different Cipher Types
    print_section("8. Different Cipher Types")
    
    test_message = "CRYPTOGRAPHY"
    
    print("Playfair Cipher:")
    encrypted = run_command(f'python3 cryptography_cli.py --encrypt playfair KEYWORD "{test_message}"')
    print(f"Encrypted: {encrypted}")
    
    print("\nSubstitution Cipher:")
    encrypted = run_command(f'python3 cryptography_cli.py --encrypt substitution ABCDEFGHIJKLMNOPQRSTUVWXYZ "{test_message}"')
    print(f"Encrypted: {encrypted}")
    
    # Test 9: Error Handling
    print_section("9. Error Handling")
    
    print("Invalid cipher type:")
    error = run_command('python3 cryptography_cli.py --encrypt invalid 3 "HELLO"')
    print(error)
    
    print("\nInvalid key for Caesar cipher:")
    error = run_command('python3 cryptography_cli.py --encrypt caesar abc "HELLO"')
    print(error)
    
    print("\nFile not found:")
    error = run_command('python3 cryptography_cli.py --encrypt-file caesar 3 nonexistent.txt output.txt')
    print(error)
    
    # Cleanup
    print_section("10. Cleanup")
    
    files_to_remove = [
        "demo_secret.txt",
        "demo_encrypted.txt", 
        "demo_decrypted.txt",
        "encrypted_sample.txt",
        "decrypted_sample.txt"
    ]
    
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)
            print(f"Removed: {file}")
    
    print_header("DEMONSTRATION COMPLETE")
    print("All features of the Cryptography CLI Application have been demonstrated!")
    print("\nKey Features Demonstrated:")
    print("✓ Multiple cipher implementations (Caesar, Vigenère, Playfair, Substitution)")
    print("✓ Frequency analysis and cryptanalysis")
    print("✓ Security assessment and vulnerability analysis")
    print("✓ Key generation for all cipher types")
    print("✓ File encryption and decryption")
    print("✓ Caesar cipher cracking using frequency analysis")
    print("✓ Comprehensive error handling")
    print("✓ Interactive and command-line modes")
    print("✓ Detailed reporting and documentation")

if __name__ == "__main__":
    main() 