from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from password_manager.crypto import set_user_key, get_user_key

def register(request):
    """ Reggister a new user """
    if request.method != 'POST':
        # Display blank registration form
        form = UserCreationForm()
    else:
        # Process completed form
        form = UserCreationForm(data=request.POST)
        
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
            get_user_key(request, user, password)
            print("User key set in session")
            login(request, user)
            return redirect('password_manager:index')

    # Display blank or invalid form
    context = {'form': form}
    return render(request, 'registration/login.html', context)
