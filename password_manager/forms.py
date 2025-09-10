from django import forms

from .models import Credentials

class CredentialForm(forms.ModelForm):
    """Form for adding or editing credentials"""
    
    class Meta:
        model = Credentials
        fields = ['site_name', 'username', 'password_encrypted']
        widgets = {
            'password_encrypted': forms.PasswordInput(),
        }