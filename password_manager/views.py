from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from vault_lab.crypto import decrypt_password, encrypt_password
from .forms import CredentialForm
from .models import Credential, Vault

def decrypt(self, dek):
    from vault_lab.crypto import decrypt_password
    return decrypt_password(self.encrypted_password, dek)

# Create your views here.
@login_required
def index(request):
    """The home page for password manager"""
    has_vault = False
    vault_unlocked = False

    if request.user.is_authenticated:
        has_vault = Vault.objects.filter(user=request.user).exists()
        vault_unlocked = "dek" in request.session

    return render(request, "password_manager/index.html", {
        "has_vault": has_vault,
        "vault_unlocked": vault_unlocked
    })

@login_required
def new_credential(request):
    dek = request.session.get("dek")

    if not dek:
        return redirect("unlock_vault")

    dek = bytes.fromhex(dek)
    vault = request.user.vault

    if request.method == "POST":
        form = CredentialForm(request.POST)
        if form.is_valid():
            credential = form.save(commit=False)

            credential.vault = vault
            credential.username_encrypted = encrypt_password(form.cleaned_data["username"], dek)
            credential.password_encrypted = encrypt_password(form.cleaned_data["password"], dek)

            credential.save()
            return redirect("credential")

    else:
        form = CredentialForm()

    return render(request, "password_manager/new_credential.html", {"form": form})

@login_required
def credential(request):
    dek = request.session.get("dek")

    if not dek:
        return redirect("unlock_vault")  # force unlock first

    dek = bytes.fromhex(dek)

    vault = request.user.vault
    credentials = Credential.objects.filter(vault=vault)

    decrypted_credentials = []
    for cred in credentials:
        decrypted_credentials.append({
            "site_name": cred.site_name,
            "username": decrypt_password(cred.username_encrypted, dek),
            "password": decrypt_password(cred.password_encrypted, dek),
        })

    return render(request, "password_manager/credentials.html", {
        "credentials": decrypted_credentials
    })

@login_required
def view_credential(request, credential_id):
    """View a single credential in detail"""
    credential = get_object_or_404(Credential, id=credential_id, vault=request.user.vault)
    decrypted_password = decrypt_password(request, credential.password_encrypted)
    context = {"credential": credential, "decrypted_password": decrypted_password}
    return render(request, "password_manager/view_credential.html", context)

@login_required
def edit_credential(request, credential_id):
    """Edit an existing credential"""
    credential = get_object_or_404(Credential, id=credential_id, vault=request.user.vault)

    if request.method != "POST":
        # No data submitted; create a form pre-filled with the current credential.
        try:
            decrypted_password = decrypt_password(
                request, credential.password_encrypted
            )
            initial_data = {
                "site_name": credential.site_name,
                "username": credential.username,
                "password": decrypted_password,
            }
            form = CredentialForm(initial=initial_data)
        except Exception:
            messages.error(
                request, "Error decrypting password. Please try logging in again."
            )
            form = CredentialForm(instance=credential)

    else:
        # POST data submitted; process data
        form = CredentialForm(instance=credential, data=request.POST)
        if form.is_valid():
            # update the credential
            edited_credential = form.save(commit=False)
            edited_credential.password_encrypted = encrypt_password(
                request, form.cleaned_data["password"]
            )
            edited_credential.save()
            return redirect(
                "password_manager:view_credential", credential_id=credential.id
            )

    # Display a blank or invalid form.
    context = {"form": form, "credential": credential}
    return render(request, "password_manager/edit_credential.html", context)


@login_required
def delete_credential(request, credential_id):
    """Delete an existing credential"""
    credential = get_object_or_404(Credential, id=credential_id, user=request.user)

    if request.method == "POST":
        credential.delete()
        return redirect("password_manager:credential")

    # Display a confirmation page
    context = {"credential": credential}
    return render(request, "password_manager/delete_credential.html", context)
