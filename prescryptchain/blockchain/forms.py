# -*- encoding: utf-8 -*-
# From Forms
from django import forms
from django.forms import extras
from django.core.exceptions import ValidationError
# Models
from blockchain.models import Prescription

class NewPrescriptionForm(forms.ModelForm):
    class Meta:
        model = Prescription
        fields = ('public_key', 'data')
        labels = {
            'data': 'Data:',
        }