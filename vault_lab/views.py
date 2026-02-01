from django.shortcuts import render
from django.contrib.auth.decorators import login_required

# Create your views here.
@login_required
def vault_lab_index(request):
    """Home page for the Vault Lab app"""
    return render(request, "vault_lab/home.html")

