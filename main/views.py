from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import SSHCred, ApiKey
import paramiko
from .models import SSHCred, ApiKey, ApiType
#
# # Create your views here.
#Return the list of servers on servermanager.html
def index(request):
    sshCreds = SSHCred.objects.all()
    context = {'sshCreds': sshCreds}
    return render(request, 'servermanager/servermanager.html', context)

#Return the list of API keys on apikeymanager.html
def apikeymanager(request):
    context = {'apikeys':ApiKey.objects.all()}
    return render(request, 'main/apikeymanager.html', context)

#Add API key. 2 methods: GET and POST.
def addapikey(request):
    if request.method == 'POST':
        type = request.POST['type']
        key = request.POST['key']

        apiKey = ApiKey()
        apiKey.type_id = type
        apiKey.key = key
        apiKey.save()

        return redirect(apikeymanager)
    else:
        context = {'apitypes':ApiType.objects.all(),'url':'addapikey'}
        return render(request, 'main/addapikey.html', context)

#Delete API key from database
def deleteapikey(request, apikey_id):
    apikey = ApiKey.objects.get(id=apikey_id)
    if apikey:
        apikey.delete()

    return redirect(apikeymanager)

#Edit API key. 2 methods: GET and POST.
def editapikey(request, apikey_id):
    if request.method == 'POST':
        id = request.POST['id']
        apikey = ApiKey.objects.get(id=id)
        if apikey:
            type = request.POST['type']
            key = request.POST['key']

            apikey.type_id = type
            apikey.key = key
            apikey.save()

        return redirect(apikeymanager)
    else:
        apikey = ApiKey.objects.get(id=apikey_id)
        context = {'apitypes':ApiType.objects.all(),'apikey':apikey,'url':'editapikey'}
        return render(request, 'main/addapikey.html', context)