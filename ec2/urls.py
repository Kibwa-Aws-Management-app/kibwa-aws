from django.urls import path

from . import views

app_name = "ec2"
urlpatterns = [
    path("", views.index, name="index"),
    path("inspection/", views.inspection, name="ec2"),
]