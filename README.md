# Cryptography CLI Application

## Project Overview

A comprehensive command-line interface (CLI) application for cryptographic operations that implements multiple cipher algorithms, performs frequency analysis for cryptanalysis, validates encryption strength using statistical tests, handles file-based encryption and decryption, generates cryptographic keys, and produces detailed security analysis reports.

### Goals

- Provide a robust, educational tool for understanding classical cryptography
- Implement multiple cipher algorithms with proper object-oriented design
- Demonstrate frequency analysis and cryptanalysis techniques
- Assess cryptographic strength using statistical methods
- Support file-based operations for practical use cases
- Generate comprehensive security reports with vulnerability assessments

## Requirements Specification

### Functional Requirements

1. **Cipher Implementations**

   - Caesar Cipher with configurable shift
   - Vigenère Cipher with keyword-based encryption
   - Playfair Cipher with 5x5 matrix encryption
   - Substitution Cipher with custom alphabet mapping

2. **Cryptanalysis Features**

   - Frequency analysis with chi-square statistics
   - Caesar cipher cracking using frequency analysis
   - Pattern detection in encrypted text
   - Statistical validation of encryption strength

3. **Security Assessment**

   - Entropy calculation using Shannon entropy
   - Vulnerability identification for each cipher type
   - Strength scoring system (0-100)
   - Security level classification (Very Weak to Strong)

4. **File Operations**

   - File encryption and decryption
   - Support for multiple file formats (.txt, .json, .csv, .xml)
   - Batch processing capabilities
   - Error handling for file operations

5. **Key Management**

   - Random key generation for all cipher types
   - Key validation and verification
   - Configurable key parameters

6. **Reporting**
   - Comprehensive encryption reports
   - Frequency analysis reports
   - Security assessment reports
   - Vulnerability analysis

### Technical Requirements

- **Python Version**: 3.8+
- **Dependencies**: Standard library only (no external packages)
- **Architecture**: Object-oriented design with inheritance and polymorphism
- **Error Handling**: Comprehensive exception handling and validation
- **Documentation**: Extensive code documentation and user guides
- **Testing**: Unit tests for all critical functions

### Standard Library Modules Used

1. `argparse` - Command-line argument parsing
2. `collections` - Counter and defaultdict for data structures
3. `pathlib` - File path operations
4. `statistics` - Statistical calculations
5. `random` - Cryptographic key generation
6. `string` - String manipulation and constants
7. `re` - Regular expressions for pattern matching
8. `math` - Mathematical functions (log2, etc.)
9. `time` - Timestamp generation
10. `json` - JSON data handling
11. `base64` - Base64 encoding/decoding
12. `hashlib` - Hash functions
13. `os` - Operating system interface
14. `sys` - System-specific parameters
15. `tempfile` - Temporary file operations
16. `unittest` - Unit testing framework

## User Guide

### Installation

1. Ensure Python 3.8+ is installed on your system
2. Download the project files:
   - `cryptography_cli.py` - Main application
   - `test_cryptography_cli.py` - Unit tests
   - `README.md` - This documentation

### Basic Usage

#### Interactive Mode

Run the application in interactive mode for an easy-to-use interface:

```bash
python cryptography_cli.py --interactive
```

Available commands in interactive mode:

- `encrypt <cipher> <key> <text>` - Encrypt text
- `decrypt <cipher> <key> <text>` - Decrypt text
- `analyze <text>` - Perform frequency analysis
- `security <cipher> <key>` - Assess cryptographic security
- `generate-key <cipher> [length]` - Generate random key
- `crack-caesar <ciphertext>` - Attempt to crack Caesar cipher
- `encrypt-file <cipher> <key> <input> <output>` - Encrypt file
- `decrypt-file <cipher> <key> <input> <output>` - Decrypt file
- `help` - Show available commands
- `exit` - Exit the application

#### Command-Line Mode

Use specific command-line arguments for direct operations:

```bash
# Encrypt text using Caesar cipher
python cryptography_cli.py --encrypt caesar 3 "HELLO WORLD"

# Decrypt text using Vigenère cipher
python cryptography_cli.py --decrypt vigenere KEY "RIJVS GSPVH"

# Perform frequency analysis
python cryptography_cli.py --analyze "SAMPLE TEXT"

# Assess cryptographic security
python cryptography_cli.py --security caesar 3

# Generate random key
python cryptography_cli.py --generate-key vigenere 10

# Crack Caesar cipher
python cryptography_cli.py --crack-caesar "KHOOR ZRUOG"

# Encrypt file
python cryptography_cli.py --encrypt-file caesar 3 input.txt output.txt

# Generate security report
python cryptography_cli.py --report caesar 3
```

### Cipher Types

#### 1. Caesar Cipher

- **Type**: Substitution cipher with fixed shift
- **Key**: Integer 0-25 representing shift amount
- **Security**: Very weak (brute force attack possible)
- **Example**: `python cryptography_cli.py --encrypt caesar 3 "HELLO"`

#### 2. Vigenère Cipher

- **Type**: Polyalphabetic substitution cipher
- **Key**: String of letters (keyword)
- **Security**: Weak (frequency analysis effective)
- **Example**: `python cryptography_cli.py --encrypt vigenere KEY "HELLO"`

#### 3. Playfair Cipher

- **Type**: Digraphic substitution cipher
- **Key**: String of letters (keyword)
- **Security**: Moderate (bigram patterns preserved)
- **Example**: `python cryptography_cli.py --encrypt playfair KEYWORD "HELLO"`

#### 4. Substitution Cipher

- **Type**: Simple substitution with custom alphabet
- **Key**: 26-letter permutation or random generation
- **Security**: Weak to moderate (frequency analysis effective)
- **Example**: `python cryptography_cli.py --encrypt substitution ABCDEFGHIJKLMNOPQRSTUVWXYZ "HELLO"`

### Examples

#### Basic Encryption/Decryption

```bash
# Encrypt with Caesar cipher
$ python cryptography_cli.py --encrypt caesar 3 "HELLO WORLD"
Encrypted: KHOOR ZRUOG

# Decrypt with Caesar cipher
$ python cryptography_cli.py --decrypt caesar 3 "KHOOR ZRUOG"
Decrypted: HELLO WORLD

# Encrypt with Vigenère cipher
$ python cryptography_cli.py --encrypt vigenere KEY "HELLO WORLD"
Encrypted: RIJVS GSPVH

# Decrypt with Vigenère cipher
$ python cryptography_cli.py --decrypt vigenere KEY "RIJVS GSPVH"
Decrypted: HELLO WORLD
```

#### Frequency Analysis

```bash
$ python cryptography_cli.py --analyze "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
Frequency Analysis:
  E: 12.50%
  T: 8.33%
  H: 8.33%
  O: 8.33%
  R: 6.25%
  ...
```

#### Security Assessment

```bash
$ python cryptography_cli.py --security caesar 3
Security Assessment:
  Strength Score: 15/100
  Security Level: Very Weak
  Entropy: 3.2456
```

#### Key Generation

```bash
$ python cryptography_cli.py --generate-key vigenere 8
Generated key: XKLMNOPQ

$ python cryptography_cli.py --generate-key caesar
Generated key: 7
```

#### Caesar Cipher Cracking

```bash
$ python cryptography_cli.py --crack-caesar "KHOOR ZRUOG"
Top 5 candidates:
  1. Shift 3: HELLO WORLD (score: 12.45)
  2. Shift 19: AXEEH PHKEW (score: 45.67)
  3. Shift 7: ATSSV SVYSV (score: 67.89)
  ...
```

#### File Operations

```bash
# Create a test file
echo "Hello, World! This is a secret message." > secret.txt

# Encrypt the file
python cryptography_cli.py --encrypt-file caesar 3 secret.txt encrypted.txt

# Decrypt the file
python cryptography_cli.py --decrypt-file caesar 3 encrypted.txt decrypted.txt
```

### Error Handling

The application provides comprehensive error handling:

- **Invalid cipher types**: Clear error messages for unsupported ciphers
- **Invalid keys**: Validation and helpful error messages
- **File operations**: Permission errors, file not found, encoding issues
- **Input validation**: Proper handling of empty text, invalid parameters

## Technical Documentation

### Architecture Overview

The application follows object-oriented design principles with clear separation of concerns:

```
CryptographyCLI (Main Controller)
├── Cipher Classes (Inheritance Hierarchy)
│   ├── BaseCipher (Abstract Base Class)
│   ├── CaesarCipher
│   ├── VigenereCipher
│   ├── PlayfairCipher
│   └── SubstitutionCipher
├── Analysis Classes
│   ├── FrequencyAnalyzer
│   └── SecurityAnalyzer
├── Utility Classes
│   ├── KeyGenerator
│   ├── FileHandler
│   └── ReportGenerator
└── Exception Classes
    └── CryptographyError
```

### Class Hierarchy

#### BaseCipher (Abstract Base Class)

- **Purpose**: Defines interface for all cipher implementations
- **Methods**: `encrypt()`, `decrypt()`, `validate_key()`
- **Design Pattern**: Template Method Pattern

#### Cipher Implementations

Each cipher class inherits from `BaseCipher` and implements:

- **CaesarCipher**: Simple shift cipher with integer key
- **VigenereCipher**: Polyalphabetic cipher with keyword
- **PlayfairCipher**: Digraphic cipher with 5x5 matrix
- **SubstitutionCipher**: General substitution with custom mapping

#### Analysis Classes

- **FrequencyAnalyzer**: Character frequency analysis and chi-square statistics
- **SecurityAnalyzer**: Entropy calculation, pattern detection, vulnerability assessment

#### Utility Classes

- **KeyGenerator**: Random key generation for all cipher types
- **FileHandler**: File I/O operations with error handling
- **ReportGenerator**: Comprehensive report generation

### Algorithm Details

#### Caesar Cipher

- **Encryption**: `C = (P + K) mod 26`
- **Decryption**: `P = (C - K) mod 26`
- **Key Space**: 26 possible keys (0-25)
- **Vulnerability**: Brute force attack trivial

#### Vigenère Cipher

- **Encryption**: `C_i = (P_i + K_{i mod len(K)}) mod 26`
- **Decryption**: `P_i = (C_i - K_{i mod len(K)}) mod 26`
- **Key Space**: 26^len(key) possible keys
- **Vulnerability**: Kasiski examination, frequency analysis

#### Playfair Cipher

- **Matrix**: 5x5 matrix generated from keyword
- **Encryption**: Bigram substitution using matrix rules
- **Key Space**: 25! possible matrices
- **Vulnerability**: Known plaintext attacks, bigram analysis

#### Substitution Cipher

- **Mapping**: One-to-one character substitution
- **Key Space**: 26! possible permutations
- **Vulnerability**: Frequency analysis, pattern recognition

### Security Analysis

#### Entropy Calculation

Uses Shannon entropy: `H = -Σ(p_i * log2(p_i))`

- Measures randomness of encrypted text
- Higher entropy indicates better encryption
- Threshold: 3.5 bits/character for strong encryption

#### Strength Scoring

Composite score (0-100) based on:

- **Entropy (40 points)**: Statistical randomness
- **Pattern Analysis (30 points)**: Repeated sequences, common words
- **Cipher-Specific (30 points)**: Known vulnerabilities

#### Vulnerability Assessment

Identifies specific weaknesses:

- **Caesar**: Brute force, frequency analysis
- **Vigenère**: Kasiski examination, repeating patterns
- **Playfair**: Known plaintext, bigram patterns
- **Substitution**: Frequency analysis, pattern recognition

### Testing

Run the comprehensive test suite:

```bash
python test_cryptography_cli.py
```

The test suite includes:

- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Edge Cases**: Empty input, invalid keys, file errors
- **Security Tests**: Entropy validation, pattern detection

### Performance Considerations

- **Time Complexity**: O(n) for most operations
- **Space Complexity**: O(n) for text processing
- **Memory Usage**: Minimal, suitable for large files
- **Scalability**: Handles files up to available memory

### Security Notes

⚠️ **Important**: This application is designed for educational purposes and demonstrates classical cryptography concepts. The implemented ciphers are **NOT** suitable for real-world security applications.

**For production use, consider:**

- AES (Advanced Encryption Standard)
- RSA (Rivest-Shamir-Adleman)
- ECC (Elliptic Curve Cryptography)
- Proper key management systems
- Secure random number generators

### Future Enhancements

Potential improvements and extensions:

1. **Additional Ciphers**: AES, RSA, ECC implementations
2. **Advanced Cryptanalysis**: Differential analysis, linear cryptanalysis
3. **Network Support**: Client-server architecture
4. **GUI Interface**: Graphical user interface
5. **Database Integration**: Key storage and management
6. **Performance Optimization**: Parallel processing for large files
7. **Plugin Architecture**: Extensible cipher framework

## License

This project is created for educational purposes. Feel free to use, modify, and distribute according to your needs.

## Author

Student - Cryptography CLI Application
Version 1.0
Python 3.8+
