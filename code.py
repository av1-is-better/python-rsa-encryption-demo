from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# --- Key Generation ---
def generate_keys():
    """Generates a new RSA public and private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def export_keys(private_key, public_key):
    """Exports keys to PEM format (bytes)."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # *** Change for production! ***
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

# --- Encryption ---
def encrypt_message(message, public_key):
    """Encrypts a message using the recipient's public key."""
    message_bytes = message.encode('utf-8')
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# --- Decryption ---
def decrypt_message(ciphertext, private_key):
    """Decrypts a ciphertext using the private key."""
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext_bytes.decode('utf-8')
    # Catching a general Exception is often sufficient here,
    # as InvalidPadding is a common type of error during decryption.
    # You could also inspect the exception type if needed, but often
    # "something went wrong with decryption" is enough info for the user.
    except Exception as e:
        # We can check if the error is specifically a padding error if we want,
        # but catching the general Exception handles it too.
        # if "padding" in str(e).lower(): # Simple check (less robust)
        #     return "Error: Decryption failed due to invalid padding (wrong key or corrupted data?)."
        # else:
        #     return f"An unexpected error occurred during decryption: {e}"
        
        # A more direct way if needed (requires inspecting the exception's class):
        # from cryptography.hazmat.primitives.asymmetric.padding import InvalidPadding as AsymmetricInvalidPadding # Import locally if needed

        # A simpler approach is often just to report that decryption failed:
        return f"Error: Decryption failed. This could be due to wrong key, corrupted data, or incorrect padding parameters. Details: {type(e).__name__}: {e}"


# --- Demonstration ---
if __name__ == "__main__":
    print("--- Demonstrating RSA Asymmetric Encryption ---")

    # 1. Generate Keys
    print("\nGenerating a new public/private key pair...")
    private_key, public_key = generate_keys()
    print("Key pair generated successfully.")

    # Optional: Display the keys in PEM format (how they might be stored or transmitted)
    private_pem, public_pem = export_keys(private_key, public_key)
    print("\n--- Exported Keys (for demonstration) ---")
    # print("Private Key (PEM format):") # Usually don't print private key!
    # print(private_pem.decode('utf-8'))
    print("\nPublic Key (PEM format):")
    print(public_pem.decode('utf-8'))
    print("-----------------------------------------")

    # 2. Define the message to be encrypted
    original_message = "Hello world! This is a secret message using RSA."
    print(f"\nOriginal Message: \"{original_message}\"")

    # 3. Encrypt the message using the PUBLIC key
    print("\nEncrypting the message using the public key...")
    encrypted_data = encrypt_message(original_message, public_key)
    # Printing large byte data can be messy, hex is better
    print(f"Encrypted Data (shown in hex, first 64 chars): {encrypted_data.hex()[:64]}...")
    print(f"Length of encrypted data: {len(encrypted_data)} bytes")

    # 4. Decrypt the message using the PRIVATE key
    print("\nDecrypting the message using the private key...")
    decrypted_message = decrypt_message(encrypted_data, private_key)
    print(f"Decrypted Message: \"{decrypted_message}\"")

    # 5. Verify
    if original_message == decrypted_message:
        print("\nVerification successful: Decrypted message matches the original.")
    else:
        print("\nVerification failed: Decrypted message does NOT match the original.")

    # Optional: Demonstrate decryption failure with wrong key
    print("\n--- Demonstrating Decryption Failure ---")
    print("Generating a DIFFERENT key pair...")
    wrong_private_key, _ = generate_keys()
    print("Attempting to decrypt the message with the WRONG private key...")
    failed_decryption_result = decrypt_message(encrypted_data, wrong_private_key)
    print(f"Result of decryption with wrong key: {failed_decryption_result}")