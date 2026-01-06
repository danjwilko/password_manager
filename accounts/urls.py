""" Defines URL patterns for the accounts app. """

from django.urls import path, include

from . import views

app_name = 'accounts'
urlpatterns = [
    # Custom login view overrides Django's built-in login view
    path('login/', views.custom_login, name='login'),
    # Include Django's built-in authentication URLs (login, logout, password management)
    path('', include('django.contrib.auth.urls')),
    # Registration page.
    path('register/', views.register, name='register'),
    # Password reset request page.
    path('forgotten_password/', views.forgotten_password, name='forgotten_password'),
     # Account recovery page.   
     path('recover_account/', views.recover_account, name='recover_account'),
     # Account recovery with uid and token.
    path('recover_account_confirm/<uidb64>/<token>/', views.recover_account_confirm, name='recover_account_confirm'),
    # Endpoint to wipe and reinitialize account (POST only).
    path('wipe_and_reinit/', views.wipe_and_reinit, name='wipe_and_reinit')
    
  
]
