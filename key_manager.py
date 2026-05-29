"""
Helper utility for generating and managing encryption keys
"""
import os
from crypto_utils import AESChatCrypto

def generate_key():
    """Generate a new encryption key"""
    key = AESChatCrypto.generate_key()
    key_str = AESChatCrypto.key_to_string(key)
    
    print("\n=== New Encryption Key Generated ===")
    print(f"Base64 Key: {key_str}")
    print(f"Hex Key: {key.hex()}")
    
    # Save to file
    save = input("\nSave key to file? (y/n): ").lower()
    if save == 'y':
        filename = input("Filename (default: chat_key.key): ") or 'chat_key.key'
        with open(filename, 'wb') as f:
            f.write(key)
        print(f"Key saved to {filename}")
    
    return key

def load_key():
    """Load an existing key from file"""
    filename = input("Enter key filename: ")
    try:
        key = AESChatCrypto.load_key_from_file(filename)
        print(f"\nKey loaded from {filename}")
        print(f"Base64: {AESChatCrypto.key_to_string(key)}")
        return key
    except FileNotFoundError:
        print("Key file not found!")
        return None

def test_encryption():
    """Test encryption/decryption with a key"""
    print("\n=== Testing Encryption ===")
    key = AESChatCrypto.generate_key()
    crypto = AESChatCrypto(key)
    
    test_message = "Hello, this is a secret message!"
    print(f"Original: {test_message}")
    
    encrypted = crypto.encrypt_message(test_message)
    print(f"Encrypted (base64): {encrypted}")
    
    decrypted = crypto.decrypt_message(encrypted)
    print(f"Decrypted: {decrypted}")
    
    if test_message == decrypted:
        print("✓ Test passed!")
    else:
        print("✗ Test failed!")

def main():
    print("=== Encryption Key Manager ===")
    print("1. Generate new key")
    print("2. Load existing key")
    print("3. Test encryption/decryption")
    
    choice = input("\nChoose option (1-3): ")
    
    if choice == '1':
        generate_key()
    elif choice == '2':
        load_key()
    elif choice == '3':
        test_encryption()
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()