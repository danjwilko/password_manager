from django import forms
from django.core.validators import URLValidator, RegexValidator
from .models import Credentials
import re

class CredentialForm(forms.ModelForm):
    """Form for adding or editing credentials"""
    site_name = forms.CharField(
        max_length=255,
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9\.\-\_\s]+$',
                message="Site name can only contain letters, numbers, periods, hyphens, underscores, and spaces."
            )
        ]
    )
    
    username = forms.CharField(
        max_length=255,
    )
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'id': 'password-input',
            'autocomplete': 'new-password',  # Prevent browser autofill
        }),
        required=False,
    )
    
    site_url = forms.CharField(
        max_length=2000,
        required=False,
        widget=forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'Optional: https://example.com'}),
        validators=[URLValidator(message="Enter a valid URL, including http:// or https://")]
    )
    

    class Meta:
        model = Credentials
        fields = ['site_name', 'username' , 'password', 'site_url']
        
    def clean_password(self):
        """
        Validate password strength, but only provide warnings rather than errors
        since this may be storing existing passwords that can't be changed.
        """
        password = self.cleaned_data.get('password')
        warnings = []
        
        if len(password) < 12:
            warnings.append("Password is shorter than 12 characters")
            
        if not re.search(r'[A-Z]', password):
            warnings.append("Password has no uppercase letters")
            
        if not re.search(r'[a-z]', password):
            warnings.append("Password has no lowercase letters")
            
        if not re.search(r'[0-9]', password):
            warnings.append("Password has no numbers")
            
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            warnings.append("Password has no special characters")
            
        # Add warnings to form but don't prevent submission
        if warnings:
            self.add_error('password', forms.ValidationError(
                "Warning: This password may be weak. Consider using a stronger password.",
                code='password_weak',
            ))
            
        return password