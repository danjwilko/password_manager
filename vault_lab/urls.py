from django.urls import path

from . import views

app_name = "vault_lab"
urlpatterns = [
    path("", views.vault_lab_index, name="vault_lab_index"),
    path("create/", views.create_vault, name="create_vault"),
    path("unlock/", views.unlock_vault, name="unlock_vault"),
    

    
]
