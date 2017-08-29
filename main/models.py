from django.db import models

# Create your models here.
class ApiType(models.Model):
    type_name = models.CharField(max_length=100)

    def __str__(self):
        return self.type_name

class ApiKey(models.Model):
    type = models.ForeignKey(ApiType,on_delete=models.CASCADE)
    key = models.CharField(max_length=1000)

    def __str__(self):
        return '{} ({},valid={})'.format(self.key,self.type,self.validity)

class SSHCred(models.Model):
    name = models.CharField(max_length=100)
    ip = models.CharField(max_length=50)
    port = models.IntegerField()
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=1000)
    servertype = models.CharField(max_length=1000)
    api_key = models.ForeignKey(ApiKey,on_delete=models.CASCADE,null=True,blank=True)

    def __str__(self):
        return '{} - {}@{}'.format(self.name,self.username,self.ip)