# Quantum-Resistant Adaptive Encryption System (QRAES)

## Overview
The Quantum-Resistant Adaptive Encryption System (QRAES) is a cutting-edge security solution that integrates advanced encryption methods, AI-driven threat analysis, and blockchain technology. This system offers robust, adaptive, and future-proof encryption by dynamically switching between AES and RSA encryption based on real-time threat assessments. It employs memory-hard functions and NTRU hashing to ensure quantum resistance and uses the Sawtooth blockchain for secure key management. Multi-factor and FIDO2 authentication further enhance security.

How It Works
Initialization: Generates ECDSA and RSA keys, sets up AI models, and prepares datasets for training.
Threat Analysis and Encryption: Uses AI to analyze data patterns and determine threat levels, dynamically switching encryption methods based on the analysis.
Key Management: Manages encryption keys securely using the Sawtooth blockchain, ensuring tamper-proof and transparent transactions.
Authentication: Implements multi-factor and FIDO2 authentication mechanisms to ensure that only authorized users can access the system.

**Features**

- **AES and RSA Encryption:** Fast, secure encryption methods suitable for various data protection needs.
- **Adaptive Encryption Switching:** AI-powered dynamic switching between AES and RSA based on real-time threat analysis.
- **Memory-Hard Functions:** Increased resistance to brute-force attacks through resource-intensive cryptographic functions.
- **NTRU Hashing:** Quantum-resistant hashing to protect against future quantum computing threats.
- **Blockchain Key Management:** Secure, transparent key management using the Sawtooth blockchain.
- **Multi-Factor Authentication (MFA) and FIDO2:** Strong authentication mechanisms to ensure authorized access.

**Installation**

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/qraes.git

# Navigate into the project directory
cd qraes

# Install required dependencies
pip install -r requirements.txt
