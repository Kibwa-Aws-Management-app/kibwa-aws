from django.urls import path

from . import views

app_name = "iam"
urlpatterns = [
    path("", views.index, name="index"),
    path("inspection/", views.inspection, name="iam"),
]
