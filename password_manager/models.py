
from django.db import models
from django.utils import timezone

from vault_lab.models import Vault 

class Credential(models.Model):
    vault = models.ForeignKey(Vault, on_delete=models.CASCADE,
    related_name="credentials")
    site_name = models.CharField(max_length=255)
    username_encrypted = models.BinaryField()
    password_encrypted = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.site_name} ({self.username})"
        
        
