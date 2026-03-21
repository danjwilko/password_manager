from django.db import models


# Create your models here.
class UserProfile(models.Model):
    user = models.OneToOneField("auth.User", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    last_vault_unlock = models.DateTimeField(null=True, blank=True)