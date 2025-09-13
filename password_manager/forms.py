from django import forms

from .models import Credentials

class CredentialForm(forms.ModelForm):
    """Form for adding or editing credentials"""
    password = forms.CharField(widget=forms.PasswordInput())
    
    class Meta:
        model = Credentials
        fields = ['site_name', 'username']