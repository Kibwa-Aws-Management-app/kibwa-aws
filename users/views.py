from django.contrib.auth import login, logout
from django.shortcuts import render, redirect

from users.forms import SignupForm, LoginForm, AccessKeyForm
from django.contrib.auth.decorators import login_required

from . import forms
from . import models


def index(request):
    if request.method == "GET":
        return render(request, 'index.html')
    else:
        print("뭔가 잘못됐다.")


@login_required
def accessKey(request):
    user = request.user

    if request.method == 'POST':
        form = AccessKeyForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            return redirect('users:index')
    else:
        form = AccessKeyForm()
    return render(request, 'users/accesskey.html', {"form": form})


def signupUser(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        print("valid?")
        if form.is_valid():
            if request.POST['password1'] == request.POST['password2']:
                user = form.save()
                print("save")
                login(request, user)
                return redirect('users:index')
    else:
        form = SignupForm()
    return render(request, 'users/signup.html', {"form": form})


def loginUser(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        print("hi")
        if form.is_valid():
            print(form.get_user())
            login(request, form.get_user())
            return redirect('users:index')
    else:
        form = LoginForm()
    return render(request, 'users/login.html', {'form': form})


def logoutUser(request):
    logout(request)
    return redirect('users:index')
