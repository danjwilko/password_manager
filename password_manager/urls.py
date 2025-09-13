# Defines URL patterns for the password manager

from django.urls import path
from . import views

app_name = 'password_manager'
urlpatterns = [
    # Define your URL patterns here
    path('', views.index, name='index'),
    # Show all stored credentials
    path('credentials/', views.credential, name='credential'),
    # Add a new credential
    path('new_credential/', views.new_credential, name='new_credential'),
    # View a single credential in detail
    path('credentials/<int:credential_id>/', views.view_credential, name='view_credential'),
    # Edit an existing credential
    path('credentials/<int:credential_id>/edit/', views.edit_credential, name='edit_credential'),
    # Delete credential
    path('credentials/<int:credential_id>/delete/', views.delete_credential, name='delete_credential'),
]