from django.contrib import admin
from . import models

# Register your models here.
admin.site.register(models.ApiType)
admin.site.register(models.ApiKey)
admin.site.register(models.SSHCred)