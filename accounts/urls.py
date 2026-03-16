""" Defines URL patterns for the accounts app. """

from django.urls import path, include

from . import views
app_name = 'accounts'
urlpatterns = [
    # Include the default Django auth URLs
    path('accounts/', include('django.contrib.auth.urls')),
    # Custom login view overrides Django's built-in login view
    path('login/', views.custom_login, name='login'),
    # Registration page.
    path('register/', views.register, name='register'),
    # Custom password reset - Uses Django's built-in PasswordResetView but with our custom template and form
    path('password_reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    # Password reset done page - handled by Django's built-in PasswordResetDoneView with our custom template
    path('password_reset_done/', views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    # Password reset confirm page - handled by Django's built-in PasswordResetConfirmView with our custom template and form
    path('password_reset_confirm/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    # Password reset complete page - handled by our custom view with our custom template
    path('password_reset_complete/', views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),

]
    