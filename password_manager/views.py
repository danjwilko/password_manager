from urllib import request
from django.shortcuts import render, redirect

from django.contrib.auth.decorators import login_required
from .models import Credentials
from .forms import CredentialForm


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
        # POST data submitted; process data.
        form = CredentialForm(data=request.POST)
        if form.is_valid():
            new_credential = form.save(commit=False)
            new_credential.user = request.user
            new_credential.save()
            return redirect('password_manager:credential')

    # Display a blank or invalid form.
    context = {'form': form}
    return render(request, 'password_manager/new_credential.html', context)

@login_required
def view_credential(request, credential_id):
    """View a single credential in detail"""
    credential = Credentials.objects.get(id=credential_id)
    context = {'credential': credential}
    return render(request, 'password_manager/view_credential.html', context)
