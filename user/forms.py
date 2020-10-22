from django import forms
from django.contrib.auth.forms import UserCreationForm

from . import models

class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "placeholder" : "Username",
                "value"       : "",
                "class"       : "form-control"
            }
        ))
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "placeholder" : "Password",
                "value"       : "",                
                "class"       : "form-control"
            }
        ))

class SignupForm(UserCreationForm):
    
    # email = forms.EmailField(max_length=200, help_text='Required')
    
    class Meta:
        model = models.UserProfile
        fields = ('email', 'name', 'username', 'company_site')

class PasswordResetForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={
                "placeholder" : "Enter Registered Email",
                "value"       : "",
                "class"       : "form-control",
                "autocomplete": "email"
            }
        ))


# class AgentSignupForm(UserCreationForm):
    
#     # email = forms.EmailField(max_length=200, help_text='Required')
    
#     class Meta:
#         model = models.UserProfile
#         fields = ('email', 'name', 'username',)
