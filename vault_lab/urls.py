from django.urls import path
from . import views

urlpatterns = [
    path('', views.vault_lab_index, name='vault_lab_index'),
]
