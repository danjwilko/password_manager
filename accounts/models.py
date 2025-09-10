from django.db import models

# Create your models here.
class UserProfile(models.Model):
    user = models.OneToOneField('auth.User', on_delete=models.CASCADE)
    encryption_salt = models.BinaryField(max_length=16, null=True, blank=True)