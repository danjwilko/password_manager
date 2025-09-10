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
  
]
