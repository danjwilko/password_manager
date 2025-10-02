import os
from django.db import transaction
from accounts.models import UserProfile
from password_manager.models import Credentials

transaction.atomic
def ensure_profile_and_salt_for_login(user) -> bool:
    """Ensure the user has a profile and a valid encryption salt for credential access.
    
    This function is called during user login to ensure the user can access their encrypted credentials.
    If the user has stored credentials but no encryption salt, it returns False, indicating that the user
    needs to recover their account recovery (which wipes all stored credentials).
    
    Behavior: 
    - If no profile or credentials exist: Creates a new profile with a new salt.
    - If no profile exists but credentials do: Returns False, indicating recovery is needed.
    - If profile exists with a valid salt: Returns True.(Normal login flow).
    - If profile exists, but no valid salt and credentials exist: Returns False, indicating recovery is needed.
    - If profile exists, but no valid salt and no credentials exist: Updates the profile with a new salt and returns True.
    
    Args:
        user (User): The Django user instance to check.

    Returns:
        bool: True if the user has a valid profile and salt, False if recovery is needed.
        
    Side Effects:
        - May create a UserProfile if it does not exist.
        - May add an encryption salt to an existing profile.
        - Does not modify the user's credentials.
        - Uses select_for_update to lock the profile row during the transaction (race condition prevention).
    """
    try:
        profile = UserProfile.objects.select_for_update().get(user=user)
        profile_exists = True
    except UserProfile.DoesNotExist:
        profile_exists = False
        profile = None
    
    if not profile_exists:
        if Credentials.objects.filter(user=user).only("id").exists():
            return False 
        UserProfile.objects.create(user=user, encryption_salt=os.urandom(16))
        return True
    
    if profile.encryption_salt:
        return True
    
    if Credentials.objects.filter(user=user).only("id").exists():
        return False
    
    profile.encryption_salt = os.urandom(16)
    profile.save(update_fields=['encryption_salt'])
    return True