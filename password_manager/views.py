from django.http import Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Credentials
from .forms import CredentialForm
from password_manager.crypto import decrypt_password
from password_manager.crypto import encrypt_password


# Create your views here.
@login_required
def index(request):
    """The home page for password manager"""
    return render(request, "password_manager/index.html")

@login_required
def credential(request):
    """Show all sites with stored credentials"""
    credentials = Credentials.objects.filter(user=request.user).order_by('site_name')
    context = {"credentials": credentials}
    return render(request, "password_manager/credentials.html", context)

@login_required
def new_credential(request):
    """Add a new credential"""
    if request.method != "POST":
        # No Data submitted; create a blank form.
        form = CredentialForm()
    else:               
        form = CredentialForm(data=request.POST)
        if form.is_valid():
            new_credential = form.save(commit=False)
            new_credential.user = request.user
            new_credential.password_encrypted = encrypt_password(request, form.cleaned_data['password'])
            new_credential.save()
            return redirect('password_manager:credential')

    # Display a blank or invalid form.
    context = {'form': form}
    return render(request, 'password_manager/new_credential.html', context)

@login_required
def view_credential(request, credential_id):
    """View a single credential in detail"""
    credential = get_object_or_404(Credentials, id=credential_id, user=request.user)
    decrypted_password = decrypt_password(request, credential.password_encrypted)
    context = {'credential': credential,
               'decrypted_password': decrypted_password}
    return render(request, 'password_manager/view_credential.html', context)

@login_required
def edit_credential(request, credential_id):
    """Edit an existing credential"""
    credential = get_object_or_404(Credentials, id=credential_id, user=request.user)
    
    if request.method != "POST":
        # No data submitted; create a form pre-filled with the current credential.
        try:
            decrypted_password = decrypt_password(request, credential.password_encrypted)
            initial_data = {
                'site_name': credential.site_name,
                'username': credential.username,
                'password': decrypted_password
            }
            form = CredentialForm(initial=initial_data)
        except Exception as e:
            messages.error(request, "Error decrypting password. Please try logging in again.")
            form = CredentialForm(instance=credential)
        
    else:
        # POST data submitted; process data
        form = CredentialForm(instance=credential, data=request.POST)
        if form.is_valid():
            # update the credential
            edited_credential = form.save(commit=False)
            edited_credential.password_encrypted = encrypt_password(request, form.cleaned_data['password'])
            edited_credential.save()
            return redirect('password_manager:view_credential', credential_id=credential.id)

    # Display a blank or invalid form.
    context = {'form': form, 'credential': credential}
    return render(request, 'password_manager/edit_credential.html', context)

@login_required
def delete_credential(request, credential_id):
    """Delete an existing credential"""
    credential = get_object_or_404(Credentials, id=credential_id, user=request.user)

    if request.method == "POST":
        credential.delete()
        return redirect('password_manager:credential')

    # Display a confirmation page
    context = {'credential': credential}
    return render(request, 'password_manager/delete_credential.html', context)

