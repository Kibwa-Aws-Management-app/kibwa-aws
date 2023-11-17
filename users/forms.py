from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, UserChangeForm

from users.models import User
from django import forms


class SignupForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('root_id', 'password1')

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
        return user


class AccessKeyForm(UserChangeForm):
    class Meta:
        model = User
        fields = ('key_id', 'access_key', 'aws_region')
        widgets = {
            'aws_region': forms.Select(attrs={'class': 'form-control'})
        }


class LoginForm(AuthenticationForm):
    class Meta:
        model = User
        fields = ('root_id', 'password')

