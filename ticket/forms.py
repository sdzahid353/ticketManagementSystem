
from django import forms

from .models import Ticket



class TicketCreateForm(forms.Form):
    class Meta:
        model = Ticket
        fields = '__all__'


# class TicketEditForm(forms.ModelForm):
#     class Meta:
#         model = Ticket
#         fields = ('title', 'owner', 'description',
#                   'status', 'waiting_for', 'assigned_to')
