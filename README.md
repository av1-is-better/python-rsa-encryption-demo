# python-rsa-encryption-demo

A simple Python program demonstrating the fundamental concepts of asymmetric encryption using the RSA algorithm. It shows how to generate public and private keys, encrypt a message using the public key, and decrypt it using the corresponding private key.

**Disclaimer:** This code is intended for educational and demonstration purposes only. It covers the core cryptographic operations but does not implement best practices for secure key management, storage, or distribution suitable for production environments.

## Features

*   Generates a new RSA public and private key pair.
*   Exports keys to PEM format (demonstration only).
*   Encrypts a string message using a public key with OAEP padding (a secure standard).
*   Decrypts a ciphertext using the corresponding private key.
*   Includes error handling for decryption failures (e.g., wrong key).
*   Provides a command-line interface to run the demonstration flow.

## Prerequisites

*   Python 3.6 or higher
*   The `cryptography` library

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/av1-is-better/python-rsa-encryption-demo.git
    cd python-rsa-encryption-demo
    ```

2.  **Install the required library:**
    ```bash
    pip install cryptography
    ```

## How to Run

1.  Save the Python code provided (e.g., `rsa_demo.py`) within the cloned repository directory.
2.  Run the script from your terminal:
    ```bash
    python rsa_demo.py
    ```

The script will execute the following steps:
1.  Generate a new key pair.
2.  (Optionally) Print the public and private keys in PEM format. **Note:** Printing the private key is unsafe for production.
3.  Define a sample message.
4.  Encrypt the message using the generated public key.
5.  Decrypt the resulting ciphertext using the *corresponding* private key.
6.  Verify that the decrypted message matches the original.
7.  Demonstrate a decryption failure using a *different* private key.

## Code Explanation

The core functionality is within the following functions:

*   `generate_keys()`: Creates the RSA `private_key` and derives the `public_key`.
*   `export_keys(private_key, public_key)`: Shows how to serialize the keys into PEM byte format. **Warning:** The private key export uses `NoEncryption()` for simplicity in the demo.
*   `encrypt_message(message, public_key)`: Takes a string message, encodes it to bytes, and encrypts it using the public key with `padding.OAEP`.
*   `decrypt_message(ciphertext, private_key)`: Takes the encrypted bytes and decrypts them using the private key and the *same* `padding.OAEP` settings. Includes a `try...except` block to catch decryption errors like `InvalidPadding`.

The `if __name__ == "__main__":` block orchestrates the demonstration workflow.

## Key Concepts Demonstrated

*   **Asymmetric Encryption:** Using a pair of mathematically linked keys.
*   **Public Key:** The key that can be shared freely; used for encryption.
*   **Private Key:** The secret key; must be kept confidential; used for decryption.
*   **RSA:** A widely used asymmetric encryption algorithm.
*   **Padding (OAEP):** Essential for the security of RSA encryption. It adds randomness and structure to the data before encryption, preventing certain attacks and ensuring deterministic decryption failure if the wrong key or corrupted data is used.

## Important Notes for Production

*   **Private Key Security:** Never store your private key unencrypted in a file or print it to the console in a real application. Always use strong encryption (e.g., password-based) when exporting or storing private keys: `encryption_algorithm=serialization.BestAvailableEncryption(b'your_secure_password')`.
*   **Key Management:** Securely generating, storing, distributing, and revoking keys in a production system is complex and requires a robust key management strategy (e.g., using hardware security modules - HSMs).
*   **Data Size:** RSA is typically used to encrypt relatively small amounts of data, such as a symmetric encryption key (like AES). For encrypting large files, a hybrid approach is used: encrypt the file with a randomly generated symmetric key, and then encrypt *only* the symmetric key using the recipient's public RSA key.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (or state "This code is released into the public domain for educational purposes" if you prefer not to use a formal license file).