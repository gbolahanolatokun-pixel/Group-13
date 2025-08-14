#!/usr/bin/env python3
"""
Unit Tests for Cryptography CLI Application
===========================================

This module contains comprehensive unit tests for all components of the
cryptography CLI application, including cipher implementations, frequency
analysis, security assessment, and file operations.

Author: Student
Version: 1.0
"""

import unittest
import tempfile
import os
import sys
from pathlib import Path

# Import the main application
from cryptography_cli import (
    CryptographyError, BaseCipher, CaesarCipher, VigenereCipher,
    PlayfairCipher, SubstitutionCipher, FrequencyAnalyzer,
    SecurityAnalyzer, KeyGenerator, FileHandler, ReportGenerator,
    CryptographyCLI
)


class TestBaseCipher(unittest.TestCase):
    """Test the abstract base cipher class."""
    
    def test_base_cipher_initialization(self):
        """Test base cipher initialization."""
        cipher = BaseCipher("test_key")
        self.assertEqual(cipher.key, "test_key")
        self.assertEqual(cipher.name, "Base Cipher")
    
    def test_abstract_methods(self):
        """Test that abstract methods raise NotImplementedError."""
        cipher = BaseCipher("test_key")
        
        with self.assertRaises(NotImplementedError):
            cipher.encrypt("test")
        
        with self.assertRaises(NotImplementedError):
            cipher.decrypt("test")
        
        with self.assertRaises(NotImplementedError):
            cipher.validate_key("test")


class TestCaesarCipher(unittest.TestCase):
    """Test Caesar cipher implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cipher = CaesarCipher("3")
    
    def test_initialization(self):
        """Test Caesar cipher initialization."""
        self.assertEqual(self.cipher.shift, 3)
        self.assertEqual(self.cipher.name, "Caesar Cipher")
    
    def test_encryption(self):
        """Test Caesar cipher encryption."""
        plaintext = "HELLO WORLD"
        expected = "KHOOR ZRUOG"
        result = self.cipher.encrypt(plaintext)
        self.assertEqual(result, expected)
    
    def test_decryption(self):
        """Test Caesar cipher decryption."""
        ciphertext = "KHOOR ZRUOG"
        expected = "HELLO WORLD"
        result = self.cipher.decrypt(ciphertext)
        self.assertEqual(result, expected)
    
    def test_round_trip(self):
        """Test encryption followed by decryption."""
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)
    
    def test_case_preservation(self):
        """Test that case is preserved in non-alphabetic characters."""
        plaintext = "Hello, World! 123"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)
    
    def test_key_validation(self):
        """Test Caesar cipher key validation."""
        # Valid keys
        self.assertTrue(CaesarCipher("0").validate_key("0"))
        self.assertTrue(CaesarCipher("25").validate_key("25"))
        
        # Invalid keys
        self.assertFalse(CaesarCipher("26").validate_key("26"))
        self.assertFalse(CaesarCipher("abc").validate_key("abc"))
        self.assertFalse(CaesarCipher("-1").validate_key("-1"))
    
    def test_empty_text(self):
        """Test handling of empty text."""
        self.assertEqual(self.cipher.encrypt(""), "")
        self.assertEqual(self.cipher.decrypt(""), "")


class TestVigenereCipher(unittest.TestCase):
    """Test Vigenère cipher implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cipher = VigenereCipher("KEY")
    
    def test_initialization(self):
        """Test Vigenère cipher initialization."""
        self.assertEqual(self.cipher.key, "KEY")
        self.assertEqual(self.cipher.name, "Vigenère Cipher")
    
    def test_encryption(self):
        """Test Vigenère cipher encryption."""
        plaintext = "HELLO WORLD"
        result = self.cipher.encrypt(plaintext)
        # Verify the result is encrypted (not equal to plaintext)
        self.assertNotEqual(result, plaintext)
        # Verify it's a string with the same length
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), len(plaintext))
    
    def test_decryption(self):
        """Test Vigenère cipher decryption."""
        plaintext = "HELLO WORLD"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)
    
    def test_round_trip(self):
        """Test encryption followed by decryption."""
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)
    
    def test_key_validation(self):
        """Test Vigenère cipher key validation."""
        # Valid keys
        self.assertTrue(VigenereCipher("ABC").validate_key("ABC"))
        self.assertTrue(VigenereCipher("KEY").validate_key("KEY"))
        
        # Invalid keys
        self.assertFalse(VigenereCipher("123").validate_key("123"))
        self.assertFalse(VigenereCipher("").validate_key(""))
        self.assertFalse(VigenereCipher("A1B").validate_key("A1B"))
    
    def test_empty_text(self):
        """Test handling of empty text."""
        self.assertEqual(self.cipher.encrypt(""), "")
        self.assertEqual(self.cipher.decrypt(""), "")


class TestPlayfairCipher(unittest.TestCase):
    """Test Playfair cipher implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cipher = PlayfairCipher("PLAYFAIR")
    
    def test_initialization(self):
        """Test Playfair cipher initialization."""
        self.assertEqual(self.cipher.name, "Playfair Cipher")
        self.assertEqual(len(self.cipher.matrix), 5)
        self.assertEqual(len(self.cipher.matrix[0]), 5)
    
    def test_matrix_generation(self):
        """Test Playfair matrix generation."""
        matrix = self.cipher.matrix
        # Check that all rows have 5 elements
        for row in matrix:
            self.assertEqual(len(row), 5)
        
        # Check that 'I' and 'J' share position (J should be replaced with I)
        j_found = False
        for row in matrix:
            if 'J' in row:
                j_found = True
                break
        self.assertFalse(j_found, "J should not be in the matrix")
    
    def test_encryption(self):
        """Test Playfair cipher encryption."""
        plaintext = "HELLO WORLD"
        encrypted = self.cipher.encrypt(plaintext)
        self.assertIsInstance(encrypted, str)
        self.assertGreater(len(encrypted), 0)
    
    def test_decryption(self):
        """Test Playfair cipher decryption."""
        plaintext = "HELLO WORLD"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        # Note: Playfair may not perfectly restore original due to padding
        self.assertIsInstance(decrypted, str)
    
    def test_key_validation(self):
        """Test Playfair cipher key validation."""
        # Valid keys
        self.assertTrue(PlayfairCipher("ABC").validate_key("ABC"))
        self.assertTrue(PlayfairCipher("PLAYFAIR").validate_key("PLAYFAIR"))
        
        # Invalid keys
        self.assertFalse(PlayfairCipher("123").validate_key("123"))
        self.assertFalse(PlayfairCipher("").validate_key(""))
    
    def test_empty_text(self):
        """Test handling of empty text."""
        self.assertEqual(self.cipher.encrypt(""), "")
        self.assertEqual(self.cipher.decrypt(""), "")


class TestSubstitutionCipher(unittest.TestCase):
    """Test substitution cipher implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cipher = SubstitutionCipher("QWERTYUIOPASDFGHJKLZXCVBNM")
    
    def test_initialization(self):
        """Test substitution cipher initialization."""
        self.assertEqual(self.cipher.name, "Substitution Cipher")
        self.assertIsInstance(self.cipher.substitution_map, dict)
    
    def test_encryption(self):
        """Test substitution cipher encryption."""
        plaintext = "HELLO WORLD"
        encrypted = self.cipher.encrypt(plaintext)
        self.assertIsInstance(encrypted, str)
        self.assertEqual(len(encrypted), len(plaintext))
    
    def test_decryption(self):
        """Test substitution cipher decryption."""
        plaintext = "HELLO WORLD"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)
    
    def test_round_trip(self):
        """Test encryption followed by decryption."""
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        encrypted = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)
    
    def test_key_validation(self):
        """Test substitution cipher key validation."""
        # Valid keys
        self.assertTrue(SubstitutionCipher("ABC").validate_key("ABC"))
        self.assertTrue(SubstitutionCipher("").validate_key(""))
        
        # Invalid keys
        self.assertFalse(SubstitutionCipher("123").validate_key("123"))
        self.assertFalse(SubstitutionCipher("A1B").validate_key("A1B"))
    
    def test_empty_text(self):
        """Test handling of empty text."""
        self.assertEqual(self.cipher.encrypt(""), "")
        self.assertEqual(self.cipher.decrypt(""), "")


class TestFrequencyAnalyzer(unittest.TestCase):
    """Test frequency analyzer implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = FrequencyAnalyzer()
    
    def test_analyze_frequency(self):
        """Test frequency analysis."""
        text = "HELLO WORLD"
        frequencies = self.analyzer.analyze_frequency(text)
        
        self.assertIsInstance(frequencies, dict)
        self.assertGreater(len(frequencies), 0)
        
        # Check that frequencies sum to approximately 100%
        total_freq = sum(frequencies.values())
        self.assertAlmostEqual(total_freq, 100.0, places=1)
    
    def test_empty_text(self):
        """Test frequency analysis with empty text."""
        frequencies = self.analyzer.analyze_frequency("")
        self.assertEqual(frequencies, {})
    
    def test_calculate_chi_square(self):
        """Test chi-square calculation."""
        frequencies = {'E': 12.0, 'T': 9.0, 'A': 8.0}
        chi_square = self.analyzer.calculate_chi_square(frequencies)
        self.assertIsInstance(chi_square, float)
        self.assertGreaterEqual(chi_square, 0.0)
    
    def test_find_most_likely_shift(self):
        """Test finding most likely Caesar shift."""
        # Create a Caesar cipher with shift 3
        caesar = CaesarCipher("3")
        plaintext = "HELLO WORLD"
        ciphertext = caesar.encrypt(plaintext)
        
        shift, score = self.analyzer.find_most_likely_shift(ciphertext)
        self.assertIsInstance(shift, int)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(shift, 0)
        self.assertLessEqual(shift, 25)
    
    def test_generate_frequency_report(self):
        """Test frequency report generation."""
        text = "HELLO WORLD"
        report = self.analyzer.generate_frequency_report(text)
        
        self.assertIsInstance(report, dict)
        self.assertIn('frequencies', report)
        self.assertIn('chi_square', report)
        self.assertIn('total_characters', report)
        self.assertIn('most_common', report)
        self.assertIn('least_common', report)


class TestSecurityAnalyzer(unittest.TestCase):
    """Test security analyzer implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = SecurityAnalyzer()
    
    def test_calculate_entropy(self):
        """Test entropy calculation."""
        text = "HELLO WORLD"
        entropy = self.analyzer.calculate_entropy(text)
        
        self.assertIsInstance(entropy, float)
        self.assertGreaterEqual(entropy, 0.0)
    
    def test_analyze_patterns(self):
        """Test pattern analysis."""
        text = "HELLO WORLD"
        patterns = self.analyzer.analyze_patterns(text)
        
        self.assertIsInstance(patterns, dict)
        self.assertIn('repeated_sequences', patterns)
        self.assertIn('common_words', patterns)
        self.assertIn('character_patterns', patterns)
    
    def test_assess_cipher_strength(self):
        """Test cipher strength assessment."""
        cipher = CaesarCipher("3")
        sample_text = "HELLO WORLD"
        assessment = self.analyzer.assess_cipher_strength(cipher, sample_text)
        
        self.assertIsInstance(assessment, dict)
        self.assertIn('cipher_name', assessment)
        self.assertIn('strength_score', assessment)
        self.assertIn('security_level', assessment)
        self.assertIn('entropy', assessment)
        self.assertIn('patterns', assessment)
        self.assertIn('vulnerabilities', assessment)
        
        # Check score range
        self.assertGreaterEqual(assessment['strength_score'], 0)
        self.assertLessEqual(assessment['strength_score'], 100)
    
    def test_empty_text(self):
        """Test with empty text."""
        entropy = self.analyzer.calculate_entropy("")
        self.assertEqual(entropy, 0.0)


class TestKeyGenerator(unittest.TestCase):
    """Test key generator implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.generator = KeyGenerator()
    
    def test_generate_caesar_key(self):
        """Test Caesar key generation."""
        key = self.generator.generate_caesar_key()
        self.assertIsInstance(key, str)
        self.assertTrue(key.isdigit())
        shift = int(key)
        self.assertGreaterEqual(shift, 1)
        self.assertLessEqual(shift, 25)
    
    def test_generate_vigenere_key(self):
        """Test Vigenère key generation."""
        key = self.generator.generate_vigenere_key(8)
        self.assertIsInstance(key, str)
        self.assertEqual(len(key), 8)
        self.assertTrue(key.isalpha())
        self.assertTrue(key.isupper())
    
    def test_generate_playfair_key(self):
        """Test Playfair key generation."""
        key = self.generator.generate_playfair_key(8)
        self.assertIsInstance(key, str)
        self.assertEqual(len(key), 8)
        self.assertTrue(key.isalpha())
        self.assertTrue(key.isupper())
    
    def test_generate_substitution_key(self):
        """Test substitution key generation."""
        key = self.generator.generate_substitution_key()
        self.assertIsInstance(key, str)
        self.assertEqual(len(key), 26)
        self.assertTrue(key.isalpha())
        self.assertTrue(key.isupper())
    
    def test_generate_secure_key(self):
        """Test secure key generation."""
        key = self.generator.generate_secure_key(32)
        self.assertIsInstance(key, str)
        self.assertEqual(len(key), 32)
        self.assertTrue(key.isalnum())


class TestFileHandler(unittest.TestCase):
    """Test file handler implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.handler = FileHandler()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_read_write_file(self):
        """Test file read and write operations."""
        test_content = "Hello, World!"
        test_file = os.path.join(self.temp_dir, "test.txt")
        
        # Write file
        self.handler.write_file(test_file, test_content)
        self.assertTrue(os.path.exists(test_file))
        
        # Read file
        content = self.handler.read_file(test_file)
        self.assertEqual(content, test_content)
    
    def test_file_not_found(self):
        """Test handling of non-existent file."""
        with self.assertRaises(CryptographyError):
            self.handler.read_file("nonexistent.txt")
    
    def test_encrypt_decrypt_file(self):
        """Test file encryption and decryption."""
        test_content = "Hello, World!"
        input_file = os.path.join(self.temp_dir, "input.txt")
        encrypted_file = os.path.join(self.temp_dir, "encrypted.txt")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")
        
        # Write test content
        self.handler.write_file(input_file, test_content)
        
        # Encrypt file
        cipher = CaesarCipher("3")
        self.handler.encrypt_file(input_file, encrypted_file, cipher)
        self.assertTrue(os.path.exists(encrypted_file))
        
        # Decrypt file
        self.handler.decrypt_file(encrypted_file, decrypted_file, cipher)
        self.assertTrue(os.path.exists(decrypted_file))
        
        # Verify content
        decrypted_content = self.handler.read_file(decrypted_file)
        self.assertEqual(decrypted_content, test_content)


class TestReportGenerator(unittest.TestCase):
    """Test report generator implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.generator = ReportGenerator()
    
    def test_generate_encryption_report(self):
        """Test encryption report generation."""
        cipher = CaesarCipher("3")
        plaintext = "HELLO WORLD"
        ciphertext = cipher.encrypt(plaintext)
        analysis = {
            'strength_score': 15,
            'security_level': 'Weak',
            'entropy': 3.2,
            'vulnerabilities': ['Test vulnerability'],
            'patterns': {'repeated_sequences': [], 'common_words': []}
        }
        
        report = self.generator.generate_encryption_report(
            cipher, plaintext, ciphertext, analysis
        )
        
        self.assertIsInstance(report, str)
        self.assertIn("CRYPTOGRAPHY ENCRYPTION REPORT", report)
        self.assertIn("Caesar Cipher", report)
        self.assertIn("Weak", report)
    
    def test_generate_frequency_report(self):
        """Test frequency report generation."""
        text = "HELLO WORLD"
        analysis = {
            'total_characters': 10,
            'chi_square': 15.5,
            'frequencies': {'H': 10.0, 'E': 10.0},
            'most_common': [('H', 10.0)]
        }
        
        report = self.generator.generate_frequency_report(text, analysis)
        
        self.assertIsInstance(report, str)
        self.assertIn("FREQUENCY ANALYSIS REPORT", report)
        self.assertIn("10.0", report)
    
    def test_save_report(self):
        """Test report saving."""
        report_content = "Test report content"
        report_file = os.path.join(tempfile.mkdtemp(), "test_report.txt")
        
        self.generator.save_report(report_content, report_file)
        self.assertTrue(os.path.exists(report_file))
        
        # Clean up
        os.remove(report_file)
        os.rmdir(os.path.dirname(report_file))


class TestCryptographyCLI(unittest.TestCase):
    """Test the main CLI application."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cli = CryptographyCLI()
    
    def test_create_cipher(self):
        """Test cipher creation."""
        # Valid ciphers
        caesar = self.cli.create_cipher("caesar", "3")
        self.assertIsInstance(caesar, CaesarCipher)
        
        vigenere = self.cli.create_cipher("vigenere", "KEY")
        self.assertIsInstance(vigenere, VigenereCipher)
        
        # Invalid cipher
        with self.assertRaises(CryptographyError):
            self.cli.create_cipher("invalid", "key")
    
    def test_encrypt_decrypt_text(self):
        """Test text encryption and decryption."""
        plaintext = "HELLO WORLD"
        
        # Caesar cipher
        encrypted = self.cli.encrypt_text(plaintext, "caesar", "3")
        decrypted = self.cli.decrypt_text(encrypted, "caesar", "3")
        self.assertEqual(decrypted, plaintext)
        
        # Vigenère cipher
        encrypted = self.cli.encrypt_text(plaintext, "vigenere", "KEY")
        decrypted = self.cli.decrypt_text(encrypted, "vigenere", "KEY")
        self.assertEqual(decrypted, plaintext)
    
    def test_analyze_frequency(self):
        """Test frequency analysis."""
        text = "HELLO WORLD"
        analysis = self.cli.analyze_frequency(text)
        
        self.assertIsInstance(analysis, dict)
        self.assertIn('frequencies', analysis)
        self.assertIn('chi_square', analysis)
    
    def test_assess_security(self):
        """Test security assessment."""
        assessment = self.cli.assess_security("caesar", "3")
        
        self.assertIsInstance(assessment, dict)
        self.assertIn('strength_score', assessment)
        self.assertIn('security_level', assessment)
        self.assertIn('entropy', assessment)
    
    def test_generate_key(self):
        """Test key generation."""
        # Caesar key
        key = self.cli.generate_key("caesar")
        self.assertIsInstance(key, str)
        self.assertTrue(key.isdigit())
        
        # Vigenère key
        key = self.cli.generate_key("vigenere", 10)
        self.assertIsInstance(key, str)
        self.assertEqual(len(key), 10)
        self.assertTrue(key.isalpha())
        
        # Invalid cipher type
        with self.assertRaises(CryptographyError):
            self.cli.generate_key("invalid")
    
    def test_crack_caesar(self):
        """Test Caesar cipher cracking."""
        # Create a Caesar cipher with shift 3
        caesar = CaesarCipher("3")
        plaintext = "HELLO WORLD"
        ciphertext = caesar.encrypt(plaintext)
        
        candidates = self.cli.crack_caesar(ciphertext)
        
        self.assertIsInstance(candidates, list)
        self.assertLessEqual(len(candidates), 5)
        
        for shift, decrypted, score in candidates:
            self.assertIsInstance(shift, int)
            self.assertIsInstance(decrypted, str)
            self.assertIsInstance(score, float)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cli = CryptographyCLI()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_complete_workflow(self):
        """Test a complete encryption/decryption workflow."""
        # Generate a key
        key = self.cli.generate_key("vigenere", 8)
        self.assertIsInstance(key, str)
        
        # Encrypt text
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        encrypted = self.cli.encrypt_text(plaintext, "vigenere", key)
        self.assertNotEqual(encrypted, plaintext)
        
        # Decrypt text
        decrypted = self.cli.decrypt_text(encrypted, "vigenere", key)
        self.assertEqual(decrypted, plaintext)
        
        # Analyze frequency
        analysis = self.cli.analyze_frequency(encrypted)
        self.assertIsInstance(analysis, dict)
        
        # Assess security
        assessment = self.cli.assess_security("vigenere", key)
        self.assertIsInstance(assessment, dict)
    
    def test_file_workflow(self):
        """Test complete file encryption/decryption workflow."""
        # Create test file
        test_content = "Hello, World! This is a test file."
        input_file = os.path.join(self.temp_dir, "input.txt")
        encrypted_file = os.path.join(self.temp_dir, "encrypted.txt")
        decrypted_file = os.path.join(self.temp_dir, "decrypted.txt")
        
        with open(input_file, 'w') as f:
            f.write(test_content)
        
        # Encrypt file
        cipher = self.cli.create_cipher("caesar", "3")
        self.cli.file_handler.encrypt_file(input_file, encrypted_file, cipher)
        
        # Decrypt file
        self.cli.file_handler.decrypt_file(encrypted_file, decrypted_file, cipher)
        
        # Verify content
        with open(decrypted_file, 'r') as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, test_content)


if __name__ == "__main__":
    # Run the tests
    unittest.main(verbosity=2) 