# sample_app/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("", views.sample_app_view, name="sample-app-view"),
]
