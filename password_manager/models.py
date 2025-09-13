from django.db import models
from django.contrib.auth.models import User


class Credentials(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    site_name = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    password_encrypted = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.site_name} ({self.username})"
    

    def set_username(self, username: str):
        self.username = username
    
    def set_site_name(self, site_name: str):
        self.site_name = site_name
        

