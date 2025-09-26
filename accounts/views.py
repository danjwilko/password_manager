from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, authenticate, get_user_model
from django.contrib.auth.forms import AuthenticationForm
from .forms import SecureUserCreationForm
from password_manager.crypto import set_user_key, get_user_key
from password_manager .models import Credentials
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from accounts.utils import ensure_profile_and_salt_for_login
from accounts.models import UserProfile
from django.db import transaction
import os

def register(request):
    """ Reggister a new user with secure password requirements"""
    if request.method != 'POST':
        # Display blank registration form
        form = SecureUserCreationForm()
    else:
        # Process completed form
        form = SecureUserCreationForm(data=request.POST)

        if form.is_valid():
            new_user = form.save()
            # Derive encryption key from password
            # Get the plaintext password.
            password = form.cleaned_data['password1']
            # Set the user's encryption key
            from password_manager.crypto import set_user_key
            set_user_key(request, new_user, password)
            # Log the user in and then redirect to home page
            login(request, new_user)
            request.session.set_expiry(300)  # Set session to expire in 5 minutes
            return redirect('password_manager:index')
    
    # Display blank or invalid form
    context = {'form': form}
    return render(request, 'registration/register.html', context)

def custom_login(request):
    print("Custom login view called")
    """ Log in an existing user """
    if request.method != 'POST':
        # Display blank login form
        form = AuthenticationForm()
    else:
        # Process completed form
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            password = form.cleaned_data['password']
            ok = ensure_profile_and_salt_for_login(user)
            if not ok:
                request.session['user_needs_recovery'] = user.pk
                messages.error(request, "Account requires recovery due to missing encryption salt. Please recover your account.")
                return redirect('accounts:recover_account')
            else:
                # Derive and store encryption key in session
                get_user_key(request, user, password)
                login(request, user)
                request.session.set_expiry(300)  # Set session to expire in 5 minutes
                return redirect('password_manager:index')

    # Display blank or invalid form
    context = {'form': form}
    return render(request, 'registration/login.html', context)

def forgotten_password(request):
    """ Display forgotten password page """
    context = {}
    return render(request, 'registration/forgotten_password.html', context)

def recover_account(request):
    if 'user_needs_recovery' not in request.session:
        return redirect('accounts:login')
    else:
        user_id = request.session['user_needs_recovery']
        context = {'form': AuthenticationForm()}
        return render(request, 'registration/recover_account.html', context)

User = get_user_model()

@require_POST
def wipe_and_reinit(request):
    # Ensure this is a POST request to prevent CSRF
    username = request.POST.get('username')
    password = request.POST.get('password')
    # Validate input
    if not username or not password:
        messages.error(request, "Username and password are required.")
        return redirect('accounts:recover_account') 
    
    # Check checkbox has been ticked
    if 'confirm_reset' not in request.POST:
        messages.error(request, "You must confirm the action.")
        return redirect('accounts:recover_account')
    
    # Authenticate user credentials
    user = authenticate(request, username=username, password=password)
    if user is None:
        messages.error(request, "Invalid username or password.")
        return redirect('accounts:recover_account')
    
    # Check if user is flagged for recovery
    flagged_user = request.session.get('user_needs_recovery')
    if flagged_user is None or int(flagged_user) != user.pk:
        messages.error(request, "Unauthorized recovery attempt.")
        return redirect('accounts:login')
    
    # Proceed with wiping credentials and reinitializing
    try:
        with transaction.atomic():
            # Delete Credentials - this is irreversible.
            Credentials.objects.filter(user=user).delete()
            # Reset or create UserProfile with new salt
            profile, created = UserProfile.objects.get_or_create(user=user)
            profile.encryption_salt = os.urandom(16)
            profile.save(update_fields=['encryption_salt'])
            
            # Derive/store encryption key
            try:
                get_user_key(request, user, password)
            except Exception:
                set_user_key(request, user, password)
                
    # If any error occurs, rollback and inform user
    except Exception as exc:
        messages.error(request, "An unexpected error occurred during recovery, please contact support.")
        return redirect('accounts:recover_account')

    # Successful recovery
    request.session.pop('user_needs_recovery', None)
    login(request, user)
    request.session.set_expiry(300)  # Session expires in 5 minutes of inactivity
    messages.success(request, "Account recovery successful. Please re-add your credentials.")
    return redirect('password_manager:index')