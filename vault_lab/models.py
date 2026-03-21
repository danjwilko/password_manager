from django.db import models
from django.conf import settings
class Vault(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="vault"
    )

    wrapped_dek = models.BinaryField(editable=False)

    kek_salt = models.BinaryField(editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Vault"