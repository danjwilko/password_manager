import os
from django.db import transaction
from accounts.models import UserProfile
from password_manager.models import Credentials

transaction.atomic
def ensure_profile_and_salt_for_login(user) -> bool:
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