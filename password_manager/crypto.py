from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.fernet import Fernet
from accounts.models import UserProfile
import base64    
import os

def create_user_key(password: str):
    """
    Create a new encryption key and salt for a user.
    
    Args:
        password (str): The user's plaintext password
        
    Returns:
        tuple: (key, salt) where key is 32 bytes derived from the password
              and salt is a random 16-byte value
    """
    salt = gen_salt() 
    key = derive_key_from_password(password, salt)
    return key, salt

def gen_salt():
    """
    Generate a cryptographically secure random salt.
    
    Returns:
        bytes: 16 random bytes suitable for cryptographic use
    """
    return os.urandom(16)

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive an encryption key from a password and salt using Argon2id.
    
    Argon2id is a memory-hard KDF that helps protect against brute force attacks.
    
    Args:
        password (str): The user's plaintext password
        salt (bytes): User-specific salt value
        
    Returns:
        bytes: 32-byte key derived from the password and salt
    """
    kdf = Argon2id(
        salt=salt,
        length=32,         # 256-bit key
        iterations=3,       # Number of iterations
        lanes=4,           # Parallelism factor
        memory_cost=64 * 1024,  # 64MB memory usage
    )
    key = kdf.derive(password.encode())
    
    return key

def set_user_key(request, user, password: str):
    """
    Create and store a new encryption key for a user.
    
    This function is called during registration or account recovery.
    It generates a new salt, derives a key, stores the salt in the database,
    and places the key in the user's session for temporary use.
    
    Args:
        request: The HTTP request object containing the session
        user: The Django user object
        password (str): The user's plaintext password
    """
    user_profile, created = UserProfile.objects.get_or_create(user=user)
    # Creating new key and salt
    key, salt = create_user_key(password)
    user_profile.encryption_salt = salt
    user_profile.save()
    # Store the key in session (temporary secure storage)
    # The key is URL-safe base64 encoded for Fernet compatibility
    key_string = base64.urlsafe_b64encode(key).decode('utf-8')
    request.session['encryption_key'] = key_string

def get_user_key(request, user, password: str):
    """
    Retrieve a user's encryption key by deriving it from their password and stored salt.
    
    This function is called during login. It retrieves the user's salt from their profile,
    re-derives the encryption key, and stores it in the session for temporary use.
    
    Args:
        request: The HTTP request object containing the session
        user: The Django user object
        password (str): The user's plaintext password
        
    Returns:
        str: URL-safe base64 encoded encryption key
        
    Raises:
        ValueError: If the user profile doesn't exist or has no encryption salt
    """
    # Retrieve user's salt and derive key
    try:
        user_profile = UserProfile.objects.get(user=user)
    except UserProfile.DoesNotExist:
        raise ValueError("User profile does not exist.")
    # Ensure salt exists
    if not user_profile.encryption_salt:
        raise ValueError("User does not have an encryption salt set.")
    key = derive_key_from_password(password, user_profile.encryption_salt)
    # Encode key to store in session
    key_string = base64.urlsafe_b64encode(key).decode('utf-8')
    request.session['encryption_key'] = key_string
    return key_string

def decrypt_password(request, encrypted_password: str) -> str:
    """
    Decrypt a stored password using the encryption key in the session.
    
    Args:
        request: The HTTP request object containing the session
        encrypted_password (str): The encrypted password string
        
    Returns:
        str: The decrypted plaintext password
        
    Raises:
        ValueError: If the encryption key is not in the session
        cryptography.fernet.InvalidToken: If decryption fails (wrong key or tampered data)
    """
    key_string = request.session.get('encryption_key')
    if not key_string:
        raise ValueError("Encryption key not found in session.")
    fernet = Fernet(key_string)
    decrypted = fernet.decrypt(encrypted_password.encode()).decode()
    return decrypted

def encrypt_password(request, password: str) -> str:
    """
    Encrypt a password using the encryption key in the session.
    
    Args:
        request: The HTTP request object containing the session
        password (str): The plaintext password to encrypt
        
    Returns:
        str: The encrypted password as a string
        
    Raises:
        ValueError: If the encryption key is not in the session
    """
    # Retrieve encryption key from session
    key_string = request.session.get('encryption_key')
    if not key_string:
        raise ValueError("Encryption key not found in session.")
    # Passing Fernet instance the key
    fernet = Fernet(key_string)
    encrypted = fernet.encrypt(password.encode())
    return encrypted.decode()