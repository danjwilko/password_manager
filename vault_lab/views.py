from django.contrib.auth.decorators import login_required
from django.shortcuts import render


# Create your views here.
@login_required
def vault_lab_index(request):
    """Home page for the Vault Lab app"""
    return render(request, "vault_lab/home.html")
