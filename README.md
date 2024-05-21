# Quantum-Resistant Adaptive Encryption System (QRAES)

## Overview
The Quantum-Resistant Adaptive Encryption System (QRAES) is a cutting-edge security solution that integrates advanced encryption methods, AI-driven threat analysis, and blockchain technology. This system offers robust, adaptive, and future-proof encryption by dynamically switching between AES and RSA encryption based on real-time threat assessments. It employs memory-hard functions and NTRU hashing to ensure quantum resistance and uses the Sawtooth blockchain for secure key management. Multi-factor and FIDO2 authentication further enhance security.

## How It Works
**Initialization:** Generates ECDSA and RSA keys, sets up AI models, and prepares datasets for training.  
**Threat Analysis and Encryption:** Uses AI to analyze data patterns and determine threat levels, dynamically switching encryption methods based on the analysis.  
**Key Management:** Manages encryption keys securely using the Sawtooth blockchain, ensuring tamper-proof and transparent transactions.  
**Authentication:** Implements multi-factor and FIDO2 authentication mechanisms to ensure that only authorized users can access the system.

## Features
- **AES and RSA Encryption:** Fast, secure encryption methods suitable for various data protection needs.
- **Adaptive Encryption Switching:** AI-powered dynamic switching between AES and RSA based on real-time threat analysis.
- **Memory-Hard Functions:** Increased resistance to brute-force attacks through resource-intensive cryptographic functions.
- **NTRU Hashing:** Quantum-resistant hashing to protect against future quantum computing threats.
- **Blockchain Key Management:** Secure, transparent key management using the Sawtooth blockchain.
- **Multi-Factor Authentication (MFA) and FIDO2:** Strong authentication mechanisms to ensure authorized access.

## Installation

### Prerequisites
- **Anaconda or Miniconda:** Make sure you have Anaconda or Miniconda installed. You can download and install it from [here](https://docs.conda.io/projects/conda/en/latest/user-guide/install/index.html).
- **Nvidia Drivers and CUDA Toolkit:** Ensure you have the appropriate Nvidia drivers and CUDA toolkit installed for GPU acceleration. Follow the [CUDA installation guide](https://docs.nvidia.com/cuda/cuda-installation-guide-linux/index.html) for your operating system.

### Step-by-Step Setup Instructions

1. **Create a New Conda Environment**
    ```bash
    conda create -n qraes_env python=3.8
    conda activate qraes_env
    ```

2. **Install Dependencies with Conda**
    ```bash
    # Install cryptographic libraries
    conda install -c conda-forge cryptography

    # Install transformers and datasets for AI model
    conda install -c conda-forge transformers datasets

    # Install PyTorch with CUDA support (adjust the CUDA version as per your setup)
    conda install pytorch torchvision torchaudio cudatoolkit=11.3 -c pytorch

    # Install additional dependencies with pip
    pip install sawtooth-sdk fido2 numpy
    ```

3. **Clone the QRAES Repository**
    ```bash
    git clone https://github.com/yourusername/qraes.git
    cd qraes
    ```

4. **Install Project-Specific Dependencies**
    Create a `requirements.txt` file with the following content:
    ```plaintext
    sawtooth-sdk
    fido2
    numpy
    secrets
    logging
    hashlib
    ```

    Then install the dependencies using pip:
    ```bash
    pip install -r requirements.txt
    ```

5. **Create a Test Script**
    Create a Python script named `test_qraes.py` with the following content to test the setup:
    ```python
    from qraes import QRAES, QRAESTransactionProcessor

    # Initialize the QRAES system
    qraes = QRAES()

    # Example usage of QRAES features
    user_id = 'example_user'
    data_pattern = "example data pattern"
    password = "strong_password"
    qraes.use_new_features(user_id, data_pattern, password)

    # Start the blockchain transaction processor
    processor = QRAESTransactionProcessor("tcp://localhost:4004")
    processor.start()
    ```

6. **Run the Test Script**
    Execute the script to verify that the setup is correct and the system works as expected:
    ```bash
    python test_qraes.py
    ```

### Full Setup Instructions

1. **Create and Activate the Conda Environment:**
    ```bash
    conda create -n qraes_env python=3.8
    conda activate qraes_env
    ```

2. **Install Dependencies:**
    ```bash
    conda install -c conda-forge cryptography transformers datasets
    conda install pytorch torchvision torchaudio cudatoolkit=11.3 -c pytorch
    pip install sawtooth-sdk fido2 numpy
    ```

3. **Clone the Repository and Navigate into the Project Directory:**
    ```bash
    git clone https://github.com/yourusername/qraes.git
    cd qraes
    ```

4. **Create and Install from `requirements.txt`:**
    Create a `requirements.txt` file with:
    ```plaintext
    sawtooth-sdk
    fido2
    numpy
    secrets
    logging
    hashlib
    ```

    Then install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

5. **Create a Test Script (`test_qraes.py`):**
    ```python
    from qraes import QRAES, QRAESTransactionProcessor

    # Initialize the QRAES system
    qraes = QRAES()

    # Example usage of QRAES features
    user_id = 'example_user'
    data_pattern = "example data pattern"
    password = "strong_password"
    qraes.use_new_features(user_id, data_pattern, password)

    # Start the blockchain transaction processor
    processor = QRAESTransactionProcessor("tcp://localhost:4004")
    processor.start()
    ```

6. **Run the Test Script:**
    ```bash
    python test_qraes.py
    ```

### Additional Considerations
- Ensure your Nvidia drivers and CUDA toolkit are correctly installed and configured for GPU acceleration.
- Adjust the CUDA version in the conda install command as per your setup (e.g., `cudatoolkit=11.3`).

By following these steps, you'll set up a new conda environment, install all necessary dependencies, and run the Quantum-Resistant Adaptive Encryption System (QRAES).
