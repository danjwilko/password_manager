from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from accounts.models import UserProfile
import base64    
import os

def create_user_key(password: str):
    salt = gen_salt()  # Generate new salt
    key = derive_key_from_password(password, salt)
    return key, salt

def gen_salt():
    return os.urandom(16)

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=64 * 1024,
    )
    key = kdf.derive(password.encode())
    
    return key

def set_user_key(request, user, password: str):
    user_profile, created = UserProfile.objects.get_or_create(user=user)
    
    key, salt = create_user_key(password)
    user_profile.encryption_salt = salt
    user_profile.save()
    # Store the key in a secure place, e.g., session or cache
    key_string = base64 .b64encode(key).decode('utf-8')
    request.session['encryption_key'] = key_string
    
def get_user_key(request, user, password: str):
    try:
        user_profile = UserProfile.objects.get(user=user)
    except UserProfile.DoesNotExist:
        raise ValueError("User profile does not exist.")
    if not user_profile.encryption_salt:
        raise ValueError("User does not have an encryption salt set.")
    key = derive_key_from_password(password, user_profile.encryption_salt)
    key_string = base64.b64encode(key).decode('utf-8')
    request.session['encryption_key'] = key_string
    return key