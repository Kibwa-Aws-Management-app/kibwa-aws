from django.urls import path

from . import views

app_name = "s3"
urlpatterns = [
    path("", views.index, name="index"),
    path("inspection/", views.inspection, name="s3"),
]
