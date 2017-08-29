from django.contrib import admin
from .models import Honeypot, Deployment

# Register your models here.
admin.site.register(Honeypot)
admin.site.register(Deployment)