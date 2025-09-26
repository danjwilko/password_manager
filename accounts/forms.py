from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import (
    UserAttributeSimilarityValidator,
    MinimumLengthValidator,
    CommonPasswordValidator,
    NumericPasswordValidator
)
from django.core.exceptions import ValidationError
import re

class StrongPasswordValidator:
    """
    Validates that a password contains at least one special character.
    """
    def validate(self, password, user=None):
        if not re.findall(r'[!@#$%^&*(),.?":|<>]', password):
            raise ValidationError(
                "Password must contain at least one special character.",
                code='password_no_special',
            )
    def get_help_text(self):
        return "Your password must contain at least one special character."
    
    
class SecureUserCreationForm(UserCreationForm):
    """ 
    A form for creating new users with enhanced security requirments.
    Includes additional password validation for stronger security.
    """
    email = forms.EmailField(required=True, help_text="Required. Enter a valid email address.")
    
    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Update password field help text
        self.fields['password1'].help_text = (
            "<ul>"
            "<li>Your password can't be too similar to your other personal information.</li>"
            "<li>Your password must contain at least 12 characters.</li>"
            "<li>Your password can't be a commonly used password.</li>"
            "<li>Your password can't be entirely numeric.</li>"
            "<li>Your password must contain at least one special character.</li>"
            "</ul>"
        )
        
    def clean_password1(self):
        """
        Apply custom password validation rules beyonf Django's defaults.
        """
        password = self.cleaned_data.get('password1')
        user = User(
            username=self.cleaned_data.get('username'),
            email=self.cleaned_data.get('email'),
        )
        
        # Run validators manually
        validators = [
            UserAttributeSimilarityValidator(),
            MinimumLengthValidator(12),# Stronger: requires 12 chars instead of the deafult 8
            CommonPasswordValidator(),
            NumericPasswordValidator(),
            StrongPasswordValidator()
        ]
        
        for validator in validators:
            validator.validate(password, user)
            
        return password
    
    def clean_email(self):
        """
        Verify that the email is unique.
        """
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("A user with that email already exists.")
        return email
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user
    