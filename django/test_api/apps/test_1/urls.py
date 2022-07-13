# test_1/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("", views.sample_app_view, name="test-app-view"),
]
