from django.db import models


class Vulnerability(models.Model):
    service = models.CharField(max_length=1000)
    lowest_version = models.CharField(max_length=1000)
    highest_version = models.CharField(max_length=1000)

    def __str__(self):
        return self.service
