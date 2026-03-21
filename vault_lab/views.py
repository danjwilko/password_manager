from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render, redirect
from password_manager.forms import CredentialForm
from password_manager.models import Credential
from vault_lab.crypto import encrypt_password, gen_dek, gen_salt, derive_kek, unwrap_dek, wrap_dek
from .models import Vault



# Create your views here.
@login_required
def vault_lab_index(request):
    """Home page for the Vault Lab app"""
    return render(request, "vault_lab/home.html")

@login_required
def create_vault(request):
    if request.method == "POST":
        password = request.POST.get("password")

        # 1. Generate DEK
        dek = gen_dek()

        # 2. Generate salt
        salt = gen_salt()

        # 3. Derive KEK (Argon2id)
        kek = derive_kek(password, salt)

        # 4. Encrypt DEK
        encrypted_dek = wrap_dek(dek, kek)

        # 5. Save
        Vault.objects.create(
            user=request.user,
            wrapped_dek=encrypted_dek,
            kek_salt = salt
        )

        return redirect("password_manager/credential")

    return render(request, "vault_lab/create_vault.html")

@login_required
def unlock_vault(request):
    if request.method == "POST":
        password = request.POST.get("password")

        try:
            vault = request.user.vault
        except Vault.DoesNotExist:
            messages.error(request, "Vault does not exist.")
            return redirect("create_vault")

        kek = derive_kek(password, vault.kek_salt)

        try:
            dek = unwrap_dek(vault.wrapped_dek, kek)
        except Exception:
            messages.error(request, "Invalid master password.")
            return redirect("vault_lab_index")

        # ✅ Store DEK in session (temporary)
        request.session["dek"] = dek.hex()

        return redirect("password_manager:credential")  # go to your existing credentials view

    return render(request, "vault_lab/unlock_vault.html")

