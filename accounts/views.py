from django.shortcuts import render, redirect
from django.contrib.auth import login
from .forms import SecureUserCreationForm
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.contrib.auth.forms import SetPasswordForm
from django.urls import reverse_lazy
 

def register(request):
    """ Register a new user with secure password requirements"""
    if request.method != 'POST':
        # Display blank registration form
        form = SecureUserCreationForm()
    else:
        # Process completed form
        form = SecureUserCreationForm(data=request.POST)

        if form.is_valid():
            new_user = form.save()
            # Log the user in and then redirect to home page
            login(request, new_user)
            request.session.set_expiry(300)  # Set session to expire in 5 minutes
            return redirect('password_manager:index')
    
    # Display blank or invalid form
    context = {'form': form}
    return render(request, 'registration/register.html', context)

def custom_login(request):
    """ Custom login view that sets session expiry to 5 minutes after successful login """
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            request.session.set_expiry(300)  # Set session to expire in 5 minutes
            return redirect('password_manager:index')
    else:
        form = AuthenticationForm()
    
    context = {'form': form}
    return render(request, 'registration/login.html', context)

class CustomPasswordResetView(PasswordResetView):
    """ Custom password reset view that uses our custom form and template """
    template_name = 'registration/password_reset.html'
    email_template_name = 'registration/password_reset_email.html'
    success_url = reverse_lazy('accounts:password_reset_done')
    
class CustomPasswordResetDoneView(PasswordResetDoneView):
    """ Custom password reset done view that uses our custom template """
    template_name = 'registration/password_reset_done.html'
   
    
class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    """ Custom password reset confirm view that uses our custom form and template """
    template_name = 'registration/password_reset_confirm.html'
    form_class = SetPasswordForm

class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    """ Custom password reset complete view that uses our custom template """
    template_name = 'registration/password_reset_complete.html'