"""Secret key generation and management."""
import os


def load_or_generate_secret_key(key_file: str) -> bytes:
    """
    Load existing secret key from file or generate a new one.
    
    Args:
        key_file: Path to the secret key file
        
    Returns:
        Secret key as bytes (32 bytes for AES-256)
    """
    if os.path.exists(key_file):
        with open(key_file, 'r', encoding='utf-8') as f:
            hex_key = f.read().strip()
            return bytes.fromhex(hex_key)
    else:
        return generate_new_secret_key(key_file)


def generate_new_secret_key(key_file: str) -> bytes:
    """
    Generate a new 256-bit secret key and save to file.
    
    Args:
        key_file: Path to save the secret key
        
    Returns:
        Generated secret key as bytes
    """
    new_key = os.urandom(32)
    hex_key = new_key.hex()
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(key_file) or '.', exist_ok=True)
    
    with open(key_file, 'w', encoding='utf-8') as f:
        f.write(hex_key)
    
    print("=" * 80)
    print("NEW SECRET KEY GENERATED!")
    print("=" * 80)
    print(f"Secret key: {hex_key}")
    print(f"Saved to: {key_file}")
    print("=" * 80)
    print("Please update your client with this secret key.")
    print("=" * 80)
    
    return new_key
