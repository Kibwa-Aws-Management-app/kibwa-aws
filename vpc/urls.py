from django.urls import path

from . import views

app_name = "vpc"
urlpatterns = [
    path("", views.index, name="index"),
    path("inspection/", views.inspection, name="vpc"),
]
