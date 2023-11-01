from django.urls import path

from . import views

# users/
app_name = "users"
urlpatterns = [
    path("", views.index, name="index"),
    path("signup/", views.signupUser, name="signup"),
    path("login/", views.loginUser, name="login"),
    path("logout/", views.logoutUser, name="logout"),
    path("access/", views.accessKey, name="access"),
]
