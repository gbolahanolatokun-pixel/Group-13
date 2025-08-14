#!/usr/bin/env python3
"""
Cryptography CLI Application
============================

A comprehensive command-line interface for cryptographic operations including:
- Multiple cipher algorithms (Caesar, Vigenère, Playfair, Substitution)
- Frequency analysis for cipher breaking
- Statistical validation of encryption strength
- File-based encryption and decryption
- Cryptographic key generation
- Security analysis reports

Author: Student
Version: 1.0
Python Version: 3.8+
"""

import argparse
import sys
import os
import json
import statistics
import random
import string
import re
from typing import Dict, List, Tuple, Optional, Any
from collections import Counter, defaultdict
from pathlib import Path
import base64
import hashlib
import time
import math


class CryptographyError(Exception):
    """Custom exception for cryptography-related errors."""
    pass


class BaseCipher:
    """Abstract base class for all cipher implementations."""
    
    def __init__(self, key: str = ""):
        self.key = key
        self.name = "Base Cipher"
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement encrypt method")
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement decrypt method")
    
    def validate_key(self, key: str) -> bool:
        """Validate the cryptographic key. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement validate_key method")


class CaesarCipher(BaseCipher):
    """Implementation of the Caesar cipher with shift key."""
    
    def __init__(self, key: str = "3"):
        super().__init__(key)
        self.name = "Caesar Cipher"
        self.shift = int(key) if key.isdigit() else 3
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt text using Caesar cipher."""
        if not plaintext:
            return ""
        
        result = ""
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset + self.shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt text using Caesar cipher."""
        if not ciphertext:
            return ""
        
        result = ""
        for char in ciphertext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset - self.shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result
    
    def validate_key(self, key: str) -> bool:
        """Validate Caesar cipher key (must be integer 0-25)."""
        try:
            shift = int(key)
            return 0 <= shift <= 25
        except ValueError:
            return False


class VigenereCipher(BaseCipher):
    """Implementation of the Vigenère cipher."""
    
    def __init__(self, key: str = "KEY"):
        super().__init__(key)
        self.name = "Vigenère Cipher"
        self.key = key.upper()
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt text using Vigenère cipher."""
        if not plaintext or not self.key:
            return plaintext
        
        result = ""
        key_length = len(self.key)
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                key_char = self.key[key_index % key_length]
                key_shift = ord(key_char) - ord('A')
                
                shifted = (ord(char) - ascii_offset + key_shift) % 26
                result += chr(shifted + ascii_offset)
                key_index += 1
            else:
                result += char
        return result
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt text using Vigenère cipher."""
        if not ciphertext or not self.key:
            return ciphertext
        
        result = ""
        key_length = len(self.key)
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                key_char = self.key[key_index % key_length]
                key_shift = ord(key_char) - ord('A')
                
                shifted = (ord(char) - ascii_offset - key_shift) % 26
                result += chr(shifted + ascii_offset)
                key_index += 1
            else:
                result += char
        return result
    
    def validate_key(self, key: str) -> bool:
        """Validate Vigenère cipher key (must contain only letters)."""
        return bool(key and key.replace(' ', '').isalpha())


class PlayfairCipher(BaseCipher):
    """Implementation of the Playfair cipher."""
    
    def __init__(self, key: str = "PLAYFAIR"):
        super().__init__(key)
        self.name = "Playfair Cipher"
        self.matrix = self._generate_matrix(key.upper())
    
    def _generate_matrix(self, key: str) -> List[List[str]]:
        """Generate 5x5 Playfair matrix from key."""
        # Remove duplicates and 'J' (I and J share position)
        key_chars = []
        for char in key.upper():
            if char.isalpha() and char != 'J' and char not in key_chars:
                key_chars.append(char)
        
        # Add remaining alphabet characters
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J
        for char in alphabet:
            if char not in key_chars:
                key_chars.append(char)
        
        # Create 5x5 matrix
        matrix = []
        for i in range(5):
            row = key_chars[i*5:(i+1)*5]
            matrix.append(row)
        
        return matrix
    
    def _find_position(self, char: str) -> Tuple[int, int]:
        """Find position of character in matrix."""
        char = char.upper()
        if char == 'J':
            char = 'I'
        
        for i, row in enumerate(self.matrix):
            for j, cell in enumerate(row):
                if cell == char:
                    return i, j
        return -1, -1
    
    def _get_pair(self, char1: str, char2: str) -> Tuple[str, str]:
        """Get encrypted/decrypted pair for two characters."""
        row1, col1 = self._find_position(char1)
        row2, col2 = self._find_position(char2)
        
        if row1 == row2:  # Same row
            new_col1 = (col1 + 1) % 5
            new_col2 = (col2 + 1) % 5
            return self.matrix[row1][new_col1], self.matrix[row2][new_col2]
        elif col1 == col2:  # Same column
            new_row1 = (row1 + 1) % 5
            new_row2 = (row2 + 1) % 5
            return self.matrix[new_row1][col1], self.matrix[new_row2][col2]
        else:  # Rectangle
            return self.matrix[row1][col2], self.matrix[row2][col1]
    
    def _get_decrypt_pair(self, char1: str, char2: str) -> Tuple[str, str]:
        """Get decrypted pair for two characters."""
        row1, col1 = self._find_position(char1)
        row2, col2 = self._find_position(char2)
        
        if row1 == row2:  # Same row
            new_col1 = (col1 - 1) % 5
            new_col2 = (col2 - 1) % 5
            return self.matrix[row1][new_col1], self.matrix[row2][new_col2]
        elif col1 == col2:  # Same column
            new_row1 = (row1 - 1) % 5
            new_row2 = (row2 - 1) % 5
            return self.matrix[new_row1][col1], self.matrix[new_row2][col2]
        else:  # Rectangle
            return self.matrix[row1][col2], self.matrix[row2][col1]
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt text using Playfair cipher."""
        if not plaintext:
            return ""
        
        # Prepare text: remove spaces, replace J with I, add X if needed
        text = plaintext.upper().replace(' ', '').replace('J', 'I')
        
        # Add X between repeated letters
        i = 0
        while i < len(text) - 1:
            if text[i] == text[i + 1]:
                text = text[:i + 1] + 'X' + text[i + 1:]
            i += 2
        
        # Add X if odd length
        if len(text) % 2 == 1:
            text += 'X'
        
        result = ""
        for i in range(0, len(text), 2):
            char1, char2 = text[i], text[i + 1]
            enc1, enc2 = self._get_pair(char1, char2)
            result += enc1 + enc2
        
        return result
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt text using Playfair cipher."""
        if not ciphertext:
            return ""
        
        result = ""
        for i in range(0, len(ciphertext), 2):
            char1, char2 = ciphertext[i], ciphertext[i + 1]
            dec1, dec2 = self._get_decrypt_pair(char1, char2)
            result += dec1 + dec2
        
        return result
    
    def validate_key(self, key: str) -> bool:
        """Validate Playfair cipher key (must contain only letters)."""
        return bool(key and key.replace(' ', '').isalpha())


class SubstitutionCipher(BaseCipher):
    """Implementation of a simple substitution cipher."""
    
    def __init__(self, key: str = ""):
        super().__init__(key)
        self.name = "Substitution Cipher"
        self.substitution_map = self._generate_substitution(key)
    
    def _generate_substitution(self, key: str) -> Dict[str, str]:
        """Generate substitution mapping from key."""
        if not key:
            # Generate random substitution
            alphabet = list(string.ascii_uppercase)
            shuffled = alphabet.copy()
            random.shuffle(shuffled)
            return dict(zip(alphabet, shuffled))
        
        # Use provided key as substitution
        key = key.upper()
        alphabet = string.ascii_uppercase
        substitution = {}
        
        for i, char in enumerate(alphabet):
            if i < len(key):
                substitution[char] = key[i]
            else:
                # Fill remaining with unused characters
                used_chars = set(substitution.values())
                remaining = [c for c in alphabet if c not in used_chars]
                if remaining:
                    substitution[char] = remaining[0]
        
        return substitution
    
    def _reverse_substitution(self) -> Dict[str, str]:
        """Generate reverse substitution mapping for decryption."""
        return {v: k for k, v in self.substitution_map.items()}
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt text using substitution cipher."""
        if not plaintext:
            return ""
        
        result = ""
        for char in plaintext:
            if char.isalpha():
                upper_char = char.upper()
                if upper_char in self.substitution_map:
                    result += self.substitution_map[upper_char]
                else:
                    result += char
            else:
                result += char
        return result
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt text using substitution cipher."""
        if not ciphertext:
            return ""
        
        reverse_map = self._reverse_substitution()
        result = ""
        for char in ciphertext:
            if char.isalpha():
                upper_char = char.upper()
                if upper_char in reverse_map:
                    result += reverse_map[upper_char]
                else:
                    result += char
            else:
                result += char
        return result
    
    def validate_key(self, key: str) -> bool:
        """Validate substitution cipher key."""
        if not key:
            return True  # Random key is valid
        return len(key) <= 26 and key.replace(' ', '').isalpha() 


class FrequencyAnalyzer:
    """Analyze frequency patterns in text for cryptanalysis."""
    
    def __init__(self):
        self.english_frequencies = {
            'E': 12.02, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 7.31,
            'N': 6.95, 'S': 6.28, 'R': 6.02, 'H': 5.92, 'D': 4.32,
            'L': 3.98, 'U': 2.88, 'C': 2.71, 'M': 2.61, 'F': 2.30,
            'Y': 2.11, 'W': 2.09, 'G': 2.03, 'P': 1.82, 'B': 1.49,
            'V': 1.11, 'K': 0.69, 'X': 0.17, 'Q': 0.11, 'J': 0.10, 'Z': 0.07
        }
    
    def analyze_frequency(self, text: str) -> Dict[str, float]:
        """Calculate character frequencies in text."""
        if not text:
            return {}
        
        # Count characters
        char_count = Counter(char.upper() for char in text if char.isalpha())
        total_chars = sum(char_count.values())
        
        if total_chars == 0:
            return {}
        
        # Calculate percentages
        frequencies = {}
        for char, count in char_count.items():
            frequencies[char] = (count / total_chars) * 100
        
        return frequencies
    
    def calculate_chi_square(self, observed_freq: Dict[str, float]) -> float:
        """Calculate chi-square statistic for frequency analysis."""
        chi_square = 0.0
        
        for char in string.ascii_uppercase:
            observed = observed_freq.get(char, 0.0)
            expected = self.english_frequencies.get(char, 0.0)
            
            if expected > 0:
                chi_square += ((observed - expected) ** 2) / expected
        
        return chi_square
    
    def find_most_likely_shift(self, ciphertext: str) -> Tuple[int, float]:
        """Find most likely Caesar cipher shift using frequency analysis."""
        best_shift = 0
        best_score = float('inf')
        
        for shift in range(26):
            caesar = CaesarCipher(str(shift))
            decrypted = caesar.decrypt(ciphertext)
            freq = self.analyze_frequency(decrypted)
            score = self.calculate_chi_square(freq)
            
            if score < best_score:
                best_score = score
                best_shift = shift
        
        return best_shift, best_score
    
    def generate_frequency_report(self, text: str) -> Dict[str, Any]:
        """Generate comprehensive frequency analysis report."""
        frequencies = self.analyze_frequency(text)
        chi_square = self.calculate_chi_square(frequencies)
        
        # Sort by frequency
        sorted_freq = sorted(frequencies.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'frequencies': dict(sorted_freq),
            'chi_square': chi_square,
            'total_characters': sum(frequencies.values()),
            'most_common': sorted_freq[:5] if sorted_freq else [],
            'least_common': sorted_freq[-5:] if sorted_freq else []
        }


class SecurityAnalyzer:
    """Analyze cryptographic strength and vulnerabilities."""
    
    def __init__(self):
        self.entropy_threshold = 3.5  # Minimum entropy for strong encryption
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        char_count = Counter(text)
        total_chars = len(text)
        entropy = 0.0
        
        for count in char_count.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_patterns(self, text: str) -> Dict[str, Any]:
        """Analyze text for cryptographic patterns."""
        patterns = {
            'repeated_sequences': [],
            'common_words': [],
            'character_patterns': {}
        }
        
        # Find repeated sequences
        for length in range(3, 8):
            for i in range(len(text) - length + 1):
                sequence = text[i:i+length]
                if text.count(sequence) > 1:
                    patterns['repeated_sequences'].append(sequence)
        
        # Find common English words
        common_words = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HER']
        text_upper = text.upper()
        for word in common_words:
            if word in text_upper:
                patterns['common_words'].append(word)
        
        # Character patterns
        patterns['character_patterns'] = {
            'consecutive_repeats': len(re.findall(r'(.)\1+', text)),
            'palindromes': len([i for i in range(len(text)-1) if text[i] == text[i+1]])
        }
        
        return patterns
    
    def assess_cipher_strength(self, cipher: BaseCipher, sample_text: str) -> Dict[str, Any]:
        """Assess the cryptographic strength of a cipher."""
        encrypted = cipher.encrypt(sample_text)
        entropy = self.calculate_entropy(encrypted)
        patterns = self.analyze_patterns(encrypted)
        
        # Calculate strength score (0-100)
        strength_score = 0
        
        # Entropy contribution (40 points)
        if entropy > 4.0:
            strength_score += 40
        elif entropy > 3.5:
            strength_score += 30
        elif entropy > 3.0:
            strength_score += 20
        else:
            strength_score += 10
        
        # Pattern analysis (30 points)
        pattern_penalty = len(patterns['repeated_sequences']) * 2
        pattern_penalty += len(patterns['common_words']) * 3
        strength_score = max(0, strength_score - pattern_penalty)
        
        # Cipher-specific analysis (30 points)
        if isinstance(cipher, CaesarCipher):
            strength_score += 5  # Very weak
        elif isinstance(cipher, VigenereCipher):
            strength_score += 15  # Weak
        elif isinstance(cipher, PlayfairCipher):
            strength_score += 25  # Moderate
        elif isinstance(cipher, SubstitutionCipher):
            strength_score += 20  # Weak to moderate
        
        strength_score = min(100, strength_score)
        
        # Determine security level
        if strength_score >= 80:
            security_level = "Strong"
        elif strength_score >= 60:
            security_level = "Moderate"
        elif strength_score >= 40:
            security_level = "Weak"
        else:
            security_level = "Very Weak"
        
        return {
            'cipher_name': cipher.name,
            'strength_score': strength_score,
            'security_level': security_level,
            'entropy': entropy,
            'patterns': patterns,
            'vulnerabilities': self._identify_vulnerabilities(cipher, patterns)
        }
    
    def _identify_vulnerabilities(self, cipher: BaseCipher, patterns: Dict[str, Any]) -> List[str]:
        """Identify potential vulnerabilities in the cipher."""
        vulnerabilities = []
        
        if isinstance(cipher, CaesarCipher):
            vulnerabilities.extend([
                "Brute force attack possible (only 25 possible keys)",
                "Frequency analysis highly effective",
                "No key management complexity"
            ])
        elif isinstance(cipher, VigenereCipher):
            vulnerabilities.extend([
                "Kasiski examination can reveal key length",
                "Frequency analysis effective once key length is known",
                "Repeating key pattern"
            ])
        elif isinstance(cipher, PlayfairCipher):
            vulnerabilities.extend([
                "Known plaintext attacks possible",
                "Frequency analysis still applicable",
                "Bigram patterns preserved"
            ])
        elif isinstance(cipher, SubstitutionCipher):
            vulnerabilities.extend([
                "Frequency analysis highly effective",
                "Pattern analysis can reveal mappings",
                "No key schedule"
            ])
        
        if patterns['repeated_sequences']:
            vulnerabilities.append("Repeated sequences detected")
        
        if patterns['common_words']:
            vulnerabilities.append("Common words detected in ciphertext")
        
        return vulnerabilities


class KeyGenerator:
    """Generate cryptographic keys with specified parameters."""
    
    def __init__(self):
        self.random = random.Random()
    
    def generate_caesar_key(self) -> str:
        """Generate random Caesar cipher key."""
        return str(self.random.randint(1, 25))
    
    def generate_vigenere_key(self, length: int = 8) -> str:
        """Generate random Vigenère cipher key."""
        if length < 1:
            length = 8
        return ''.join(self.random.choices(string.ascii_uppercase, k=length))
    
    def generate_playfair_key(self, length: int = 8) -> str:
        """Generate random Playfair cipher key."""
        if length < 1:
            length = 8
        return ''.join(self.random.choices(string.ascii_uppercase, k=min(length, 25)))
    
    def generate_substitution_key(self) -> str:
        """Generate random substitution cipher key."""
        alphabet = list(string.ascii_uppercase)
        self.random.shuffle(alphabet)
        return ''.join(alphabet)
    
    def generate_secure_key(self, length: int = 32) -> str:
        """Generate cryptographically secure key."""
        return ''.join(self.random.choices(string.ascii_letters + string.digits, k=length))


class FileHandler:
    """Handle file-based encryption and decryption operations."""
    
    def __init__(self):
        self.supported_formats = ['.txt', '.json', '.csv', '.xml']
    
    def read_file(self, filepath: str) -> str:
        """Read content from file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            raise CryptographyError(f"File not found: {filepath}")
        except PermissionError:
            raise CryptographyError(f"Permission denied: {filepath}")
        except UnicodeDecodeError:
            raise CryptographyError(f"Unicode decode error in file: {filepath}")
    
    def write_file(self, filepath: str, content: str) -> None:
        """Write content to file."""
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(content)
        except PermissionError:
            raise CryptographyError(f"Permission denied: {filepath}")
        except OSError as e:
            raise CryptographyError(f"Error writing file: {e}")
    
    def encrypt_file(self, input_path: str, output_path: str, cipher: BaseCipher) -> None:
        """Encrypt file content."""
        content = self.read_file(input_path)
        encrypted_content = cipher.encrypt(content)
        self.write_file(output_path, encrypted_content)
    
    def decrypt_file(self, input_path: str, output_path: str, cipher: BaseCipher) -> None:
        """Decrypt file content."""
        content = self.read_file(input_path)
        decrypted_content = cipher.decrypt(content)
        self.write_file(output_path, decrypted_content)
    
    def batch_encrypt(self, input_dir: str, output_dir: str, cipher: BaseCipher) -> List[str]:
        """Encrypt all supported files in a directory."""
        processed_files = []
        
        try:
            input_path = Path(input_dir)
            output_path = Path(output_dir)
            output_path.mkdir(exist_ok=True)
            
            for file_path in input_path.iterdir():
                if file_path.is_file() and file_path.suffix.lower() in self.supported_formats:
                    output_file = output_path / f"{file_path.stem}_encrypted{file_path.suffix}"
                    self.encrypt_file(str(file_path), str(output_file), cipher)
                    processed_files.append(str(output_file))
        
        except Exception as e:
            raise CryptographyError(f"Batch encryption failed: {e}")
        
        return processed_files


class ReportGenerator:
    """Generate comprehensive security analysis reports."""
    
    def __init__(self):
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_encryption_report(self, cipher: BaseCipher, plaintext: str, 
                                 ciphertext: str, analysis: Dict[str, Any]) -> str:
        """Generate detailed encryption report."""
        report = f"""
=== CRYPTOGRAPHY ENCRYPTION REPORT ===
Generated: {self.timestamp}

CIPHER INFORMATION:
- Cipher Type: {cipher.name}
- Key: {cipher.key}
- Key Validation: {'Valid' if cipher.validate_key(cipher.key) else 'Invalid'}

TEXT ANALYSIS:
- Original Length: {len(plaintext)} characters
- Encrypted Length: {len(ciphertext)} characters
- Compression Ratio: {len(ciphertext)/len(plaintext)*100:.2f}%

SECURITY ASSESSMENT:
- Strength Score: {analysis.get('strength_score', 'N/A')}/100
- Security Level: {analysis.get('security_level', 'N/A')}
- Entropy: {analysis.get('entropy', 'N/A'):.4f}

VULNERABILITIES:
"""
        
        vulnerabilities = analysis.get('vulnerabilities', [])
        if vulnerabilities:
            for vuln in vulnerabilities:
                report += f"- {vuln}\n"
        else:
            report += "- No specific vulnerabilities identified\n"
        
        patterns = analysis.get('patterns', {})
        if patterns:
            report += f"""
PATTERN ANALYSIS:
- Repeated Sequences: {len(patterns.get('repeated_sequences', []))}
- Common Words Detected: {len(patterns.get('common_words', []))}
- Consecutive Repeats: {patterns.get('character_patterns', {}).get('consecutive_repeats', 0)}
"""
        
        return report
    
    def generate_frequency_report(self, text: str, analysis: Dict[str, Any]) -> str:
        """Generate frequency analysis report."""
        report = f"""
=== FREQUENCY ANALYSIS REPORT ===
Generated: {self.timestamp}

TEXT STATISTICS:
- Total Characters: {analysis.get('total_characters', 0)}
- Chi-Square Statistic: {analysis.get('chi_square', 0):.4f}

CHARACTER FREQUENCIES:
"""
        
        frequencies = analysis.get('frequencies', {})
        for char, freq in sorted(frequencies.items(), key=lambda x: x[1], reverse=True):
            report += f"- {char}: {freq:.2f}%\n"
        
        most_common = analysis.get('most_common', [])
        if most_common:
            report += f"\nMOST COMMON CHARACTERS:\n"
            for char, freq in most_common:
                report += f"- {char}: {freq:.2f}%\n"
        
        return report
    
    def save_report(self, report: str, filename: str) -> None:
        """Save report to file."""
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(report)
        except Exception as e:
            raise CryptographyError(f"Error saving report: {e}")


class CryptographyCLI:
    """Main CLI application for cryptography operations."""
    
    def __init__(self):
        self.ciphers = {
            'caesar': CaesarCipher,
            'vigenere': VigenereCipher,
            'playfair': PlayfairCipher,
            'substitution': SubstitutionCipher
        }
        self.frequency_analyzer = FrequencyAnalyzer()
        self.security_analyzer = SecurityAnalyzer()
        self.key_generator = KeyGenerator()
        self.file_handler = FileHandler()
        self.report_generator = ReportGenerator()
    
    def create_cipher(self, cipher_type: str, key: str = "") -> BaseCipher:
        """Create cipher instance based on type."""
        if cipher_type not in self.ciphers:
            raise CryptographyError(f"Unsupported cipher type: {cipher_type}")
        
        cipher_class = self.ciphers[cipher_type]
        return cipher_class(key)
    
    def encrypt_text(self, text: str, cipher_type: str, key: str = "") -> str:
        """Encrypt text using specified cipher."""
        cipher = self.create_cipher(cipher_type, key)
        return cipher.encrypt(text)
    
    def decrypt_text(self, text: str, cipher_type: str, key: str = "") -> str:
        """Decrypt text using specified cipher."""
        cipher = self.create_cipher(cipher_type, key)
        return cipher.decrypt(text)
    
    def analyze_frequency(self, text: str) -> Dict[str, Any]:
        """Perform frequency analysis on text."""
        return self.frequency_analyzer.generate_frequency_report(text)
    
    def assess_security(self, cipher_type: str, key: str = "", sample_text: str = None) -> Dict[str, Any]:
        """Assess cryptographic security."""
        if not sample_text:
            sample_text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        
        cipher = self.create_cipher(cipher_type, key)
        return self.security_analyzer.assess_cipher_strength(cipher, sample_text)
    
    def generate_key(self, cipher_type: str, length: int = 8) -> str:
        """Generate key for specified cipher type."""
        if cipher_type == 'caesar':
            return self.key_generator.generate_caesar_key()
        elif cipher_type == 'vigenere':
            return self.key_generator.generate_vigenere_key(length)
        elif cipher_type == 'playfair':
            return self.key_generator.generate_playfair_key(length)
        elif cipher_type == 'substitution':
            return self.key_generator.generate_substitution_key()
        else:
            raise CryptographyError(f"Unsupported cipher type for key generation: {cipher_type}")
    
    def crack_caesar(self, ciphertext: str) -> List[Tuple[int, str, float]]:
        """Attempt to crack Caesar cipher using frequency analysis."""
        results = []
        
        for shift in range(26):
            caesar = CaesarCipher(str(shift))
            decrypted = caesar.decrypt(ciphertext)
            freq_analysis = self.frequency_analyzer.analyze_frequency(decrypted)
            chi_square = self.frequency_analyzer.calculate_chi_square(freq_analysis)
            results.append((shift, decrypted, chi_square))
        
        # Sort by chi-square (lower is better)
        results.sort(key=lambda x: x[2])
        return results[:5]  # Return top 5 candidates
    
    def run_interactive_mode(self):
        """Run interactive CLI mode."""
        print("=== CRYPTOGRAPHY CLI ===")
        print("Available commands:")
        print("1. encrypt <cipher> <key> <text>")
        print("2. decrypt <cipher> <key> <text>")
        print("3. analyze <text>")
        print("4. security <cipher> <key>")
        print("5. generate-key <cipher> [length]")
        print("6. crack-caesar <ciphertext>")
        print("7. encrypt-file <cipher> <key> <input> <output>")
        print("8. decrypt-file <cipher> <key> <input> <output>")
        print("9. help")
        print("10. exit")
        
        while True:
            try:
                command = input("\n> ").strip()
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == 'exit':
                    print("Goodbye!")
                    break
                elif cmd == 'help':
                    print("Available commands:")
                    print("1. encrypt <cipher> <key> <text>")
                    print("2. decrypt <cipher> <key> <text>")
                    print("3. analyze <text>")
                    print("4. security <cipher> <key>")
                    print("5. generate-key <cipher> [length]")
                    print("6. crack-caesar <ciphertext>")
                    print("7. encrypt-file <cipher> <key> <input> <output>")
                    print("8. decrypt-file <cipher> <key> <input> <output>")
                    print("9. help")
                    print("10. exit")
                
                elif cmd == 'encrypt' and len(parts) >= 4:
                    cipher_type, key, text = parts[1], parts[2], ' '.join(parts[3:])
                    result = self.encrypt_text(text, cipher_type, key)
                    print(f"Encrypted: {result}")
                
                elif cmd == 'decrypt' and len(parts) >= 4:
                    cipher_type, key, text = parts[1], parts[2], ' '.join(parts[3:])
                    result = self.decrypt_text(text, cipher_type, key)
                    print(f"Decrypted: {result}")
                
                elif cmd == 'analyze' and len(parts) >= 2:
                    text = ' '.join(parts[1:])
                    analysis = self.analyze_frequency(text)
                    print(f"Frequency Analysis:")
                    for char, freq in analysis['frequencies'].items():
                        print(f"  {char}: {freq:.2f}%")
                
                elif cmd == 'security' and len(parts) >= 3:
                    cipher_type, key = parts[1], parts[2]
                    assessment = self.assess_security(cipher_type, key)
                    print(f"Security Assessment:")
                    print(f"  Strength Score: {assessment['strength_score']}/100")
                    print(f"  Security Level: {assessment['security_level']}")
                    print(f"  Entropy: {assessment['entropy']:.4f}")
                
                elif cmd == 'generate-key' and len(parts) >= 2:
                    cipher_type = parts[1]
                    length = int(parts[2]) if len(parts) > 2 else 8
                    key = self.generate_key(cipher_type, length)
                    print(f"Generated key: {key}")
                
                elif cmd == 'crack-caesar' and len(parts) >= 2:
                    ciphertext = ' '.join(parts[1:])
                    candidates = self.crack_caesar(ciphertext)
                    print("Top 5 candidates:")
                    for i, (shift, decrypted, score) in enumerate(candidates, 1):
                        print(f"  {i}. Shift {shift}: {decrypted} (score: {score:.2f})")
                
                elif cmd == 'encrypt-file' and len(parts) >= 5:
                    cipher_type, key, input_file, output_file = parts[1], parts[2], parts[3], parts[4]
                    cipher = self.create_cipher(cipher_type, key)
                    self.file_handler.encrypt_file(input_file, output_file, cipher)
                    print(f"File encrypted: {output_file}")
                
                elif cmd == 'decrypt-file' and len(parts) >= 5:
                    cipher_type, key, input_file, output_file = parts[1], parts[2], parts[3], parts[4]
                    cipher = self.create_cipher(cipher_type, key)
                    self.file_handler.decrypt_file(input_file, output_file, cipher)
                    print(f"File decrypted: {output_file}")
                
                else:
                    print("Invalid command. Type 'help' for available commands.")
            
            except CryptographyError as e:
                print(f"Error: {e}")
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")


def main():
    """Main entry point for the cryptography CLI application."""
    parser = argparse.ArgumentParser(
        description="Comprehensive Cryptography CLI Application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cryptography_cli.py --interactive
  python cryptography_cli.py --encrypt caesar 3 "HELLO WORLD"
  python cryptography_cli.py --decrypt vigenere KEY "KHOOR ZRUOG"
  python cryptography_cli.py --analyze "SAMPLE TEXT"
  python cryptography_cli.py --security caesar 3
  python cryptography_cli.py --generate-key vigenere 10
  python cryptography_cli.py --crack-caesar "KHOOR ZRUOG"
  python cryptography_cli.py --encrypt-file caesar 3 input.txt output.txt
        """
    )
    
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Run in interactive mode')
    
    # Encryption/Decryption
    parser.add_argument('--encrypt', '-e', nargs=3, metavar=('CIPHER', 'KEY', 'TEXT'),
                       help='Encrypt text using specified cipher and key')
    parser.add_argument('--decrypt', '-d', nargs=3, metavar=('CIPHER', 'KEY', 'TEXT'),
                       help='Decrypt text using specified cipher and key')
    
    # Analysis
    parser.add_argument('--analyze', '-a', metavar='TEXT',
                       help='Perform frequency analysis on text')
    parser.add_argument('--security', '-s', nargs=2, metavar=('CIPHER', 'KEY'),
                       help='Assess cryptographic security')
    
    # Key generation
    parser.add_argument('--generate-key', '-g', nargs='+', metavar=('CIPHER', '[LENGTH]'),
                       help='Generate key for specified cipher')
    
    # Cryptanalysis
    parser.add_argument('--crack-caesar', '-c', metavar='CIPHERTEXT',
                       help='Attempt to crack Caesar cipher')
    
    # File operations
    parser.add_argument('--encrypt-file', nargs=4, metavar=('CIPHER', 'KEY', 'INPUT', 'OUTPUT'),
                       help='Encrypt file')
    parser.add_argument('--decrypt-file', nargs=4, metavar=('CIPHER', 'KEY', 'INPUT', 'OUTPUT'),
                       help='Decrypt file')
    
    # Report generation
    parser.add_argument('--report', '-r', nargs=2, metavar=('CIPHER', 'KEY'),
                       help='Generate comprehensive security report')
    
    args = parser.parse_args()
    
    cli = CryptographyCLI()
    
    try:
        if args.interactive:
            cli.run_interactive_mode()
        
        elif args.encrypt:
            cipher_type, key, text = args.encrypt
            result = cli.encrypt_text(text, cipher_type, key)
            print(f"Encrypted: {result}")
        
        elif args.decrypt:
            cipher_type, key, text = args.decrypt
            result = cli.decrypt_text(text, cipher_type, key)
            print(f"Decrypted: {result}")
        
        elif args.analyze:
            analysis = cli.analyze_frequency(args.analyze)
            print("Frequency Analysis:")
            for char, freq in analysis['frequencies'].items():
                print(f"  {char}: {freq:.2f}%")
        
        elif args.security:
            cipher_type, key = args.security
            assessment = cli.assess_security(cipher_type, key)
            print(f"Security Assessment:")
            print(f"  Strength Score: {assessment['strength_score']}/100")
            print(f"  Security Level: {assessment['security_level']}")
            print(f"  Entropy: {assessment['entropy']:.4f}")
        
        elif args.generate_key:
            cipher_type = args.generate_key[0]
            length = int(args.generate_key[1]) if len(args.generate_key) > 1 else 8
            key = cli.generate_key(cipher_type, length)
            print(f"Generated key: {key}")
        
        elif args.crack_caesar:
            candidates = cli.crack_caesar(args.crack_caesar)
            print("Top 5 candidates:")
            for i, (shift, decrypted, score) in enumerate(candidates, 1):
                print(f"  {i}. Shift {shift}: {decrypted} (score: {score:.2f})")
        
        elif args.encrypt_file:
            cipher_type, key, input_file, output_file = args.encrypt_file
            cipher = cli.create_cipher(cipher_type, key)
            cli.file_handler.encrypt_file(input_file, output_file, cipher)
            print(f"File encrypted: {output_file}")
        
        elif args.decrypt_file:
            cipher_type, key, input_file, output_file = args.decrypt_file
            cipher = cli.create_cipher(cipher_type, key)
            cli.file_handler.decrypt_file(input_file, output_file, cipher)
            print(f"File decrypted: {output_file}")
        
        elif args.report:
            cipher_type, key = args.report
            cipher = cli.create_cipher(cipher_type, key)
            sample_text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
            encrypted = cipher.encrypt(sample_text)
            assessment = cli.assess_security(cipher_type, key, sample_text)
            report = cli.report_generator.generate_encryption_report(
                cipher, sample_text, encrypted, assessment
            )
            print(report)
        
        else:
            parser.print_help()
    
    except CryptographyError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 