from django import forms
from django.contrib.auth.forms import UserCreationForm

from . import models



class AdminSignupForm(UserCreationForm):
    
    # email = forms.EmailField(max_length=200, help_text='Required')
    
    class Meta:
        model = models.UserProfile
        fields = ('email', 'name', 'username', 'password', 'company_site')


class AgentSignupForm(UserCreationForm):
    
    # email = forms.EmailField(max_length=200, help_text='Required')
    
    class Meta:
        model = models.UserProfile
        fields = ('email', 'name', 'username', 'password',)
