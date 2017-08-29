import json, configparser
from main.lib import executeSSHbuffered, executeSSH, connectSSH
from django.http import HttpResponse
from django.shortcuts import render, redirect, reverse
from main.models import SSHCred, ApiKey
from honeypot.models import Honeypot
from django.http import Http404
from django.conf import settings

# Create your views here.
#Get ssh credentials from database and return it to servermanager.html for display
def ssh(request):
    sshCreds = SSHCred.objects.all()
    context = {'sshCreds':sshCreds}
    return render(request, 'servermanager/servermanager.html', context)

#Store ssh credentials in JSON format.
def sshjson(request,type=None):
    results = []

    if type:
        sshCreds = SSHCred.objects.filter(servertype=type)
    else:
        sshCreds = SSHCred.objects.all()

    for s in sshCreds:
        results.append({
            'ID': s.id,
            'Name': s.name,
            'IP': s.ip,
            'Port': s.port,
            'Username': s.username,
            'Password': s.password,
            'Type': s.servertype
        })

    return HttpResponse(json.dumps(results), content_type='application/json')

#Displays ssh credentials in table.
def sshtable(request):
    results = json.loads(sshjson(request).getvalue().decode('utf8'))
    for ssh in results:
        ssh_id = ssh['ID']

        name = '{} ({}@{})'.format(ssh['Name'],ssh['Username'],ssh['IP'])

        index = '''
            <button type="button" class="btn btn-link btn-sm icon_colororangered" onclick="showConfirmModal('{}','{}','{}')"><span class="glyphicon glyphicon-remove-circle"></span></button>
        '''.format(ssh_id,name,reverse(delete, kwargs={'ssh_id': ssh_id}))
        ssh['Index'] = index

        actions = '''
            <button type="button" class="btn btn-default btn-sm" onclick="addModal_open({})"><span class="glyphicon glyphicon-edit"></span> Edit</button>
        '''.format(ssh_id)
        ssh['Actions'] = actions

    return HttpResponse(json.dumps(results), content_type='application/json')

#Get ssh credentials from database and return it to servermanager.html for display.
def index(request):
    sshCreds = SSHCred.objects.all()
    context = {'sshCreds':sshCreds}
    return render(request, 'servermanager/servermanager.html', context)

#Adding of ssh credentials so that we can log in to the server
def addssh(request):
    if request.method == 'POST':
        sshCred = SSHCred()
        sshCred.name = request.POST['name']
        sshCred.ip = request.POST['ip']
        sshCred.port = int(request.POST['port'])
        sshCred.username = request.POST['username']
        sshCred.password = request.POST['password']
        sshCred.servertype = request.POST['servertype']
        try:
            apikey = int(request.POST['apikey'])
        except Exception as e:
            apikey = None
        sshCred.api_key_id = apikey

        if SSHCred.objects.filter(ip=request.POST['ip']).exists():
            taken = "taken"
            sshCreds = SSHCred.objects.all()
            context = {'sshCreds': sshCreds,
                       'taken':taken}
            return render(request,'servermanager/servermanager.html',context)
        elif SSHCred.objects.filter(name=request.POST['name']).exists():
            taken2 = "taken"
            sshCreds = SSHCred.objects.all()
            context = {'sshCreds': sshCreds,
                       'taken2': taken2}
            return render(request, 'servermanager/servermanager.html', context)

        if runscript(request):
            sshCred.save()
            return redirect('servermanager')
        else:
            fail = "fail"
            sshCreds = SSHCred.objects.all()
            context = {'sshCreds': sshCreds,
                       'fail': fail}
            return render(request, 'servermanager/servermanager.html', context)

    else:
        apikeys = {}
        for a in ApiKey.objects.all():
            id = a.id
            key = a.key
            type = a.type.type_name
            apikeys[id] = '%s (%s)' % (key,type)

        context = {'apikeys':apikeys}
        return render(request, 'servermanager/servermanager.html', context)

#Part 2 of edit server. Edit ssh credentials and running runscript method again to recheck all prerequisites
def editssh(request):
    if request.method=='POST':
        sshCred = SSHCred.objects.get(id=request.POST['id'])
        sshCred.name = request.POST['name']
        sshCred.port = int(request.POST['port'])
        sshCred.username = request.POST['username']
        sshCred.password = request.POST['password']


        
        if runscript(request):
            sshCred.save()
            return redirect('servermanager')
        else:
            fail = "fail"
            context = {"fail": fail}
            return render(request, 'servermanager/servermanager.html', context)



#Delete server from tool
def delete(request,ssh_id):
    #Get ssh credentials to be deleted
    ssh = SSHCred.objects.get(id=ssh_id)
    if request.method == 'POST':
        checkbox = request.POST.get("cleanup", None)

        client = connectSSH(ssh.ip, ssh.port, ssh.username, ssh.password)

        # If checkbox is honeypot, stop and remove all docker images, HOSTTool folders and credentials on tool
        if checkbox:
            if ssh.servertype == 'honeypots':
                command = '''
                          echo '{}' | sudo -S docker stop $(docker ps -a -q);
                          echo '{}' | sudo -S docker rm $(docker ps -a -q);
                          echo '{}' | sudo -S docker rmi $(docker images -q);
                          echo '{}' | sudo -S docker volume rm $(docker volume ls -f dangling=true -q);
                          cd ~;
                          echo '{}' | sudo -S rm -rf FYP-Scripts;
                          echo '{}' | sudo -S rm -rf HOSTTools;
                          '''.format(ssh.password,ssh.password,ssh.password, ssh.password, ssh.password, ssh.password)
                executeSSH(client, command)

            # If checkbox is scanning, remove all HOSTTool folders, scanning logs and credentials on tool
            elif ssh.servertype == "scanning":
                command='''
                        echo '{}' | sudo -S rm -rf FYP-Scripts;
                        echo '{}' | sudo -S rm -rf HOSTTools;
                        '''.format(ssh.password, ssh.password)
                executeSSH(client, command)

        #Remove credentials from database
        if ssh:
            ssh.delete()
    return redirect('servermanager')

def servermanager(request):
    return render(request, 'servermanager/servermanager.html')

# Install and grab the necessary prerequisites needed for the tool to work
def runscript(request):
    try:
        if 'ip' in request.POST:
            ip = request.POST['ip']
        else:
            ip = SSHCred.objects.get(id=request.POST['id']).ip

        if 'servertype' in request.POST:
            servertype = request.POST['servertype']
        else:
            servertype = SSHCred.objects.get(id=request.POST['id']).servertype

        client = connectSSH(ip, int(request.POST['port']), request.POST['username'], request.POST['password'])
        command = '''
                  echo '{}' | sudo -S rm -rf ~/FYP-Scripts/;
                  echo '{}' | sudo -S apt-get update -y;
                  echo '{}' | sudo -S apt-get install python git wget gcc make libpcap-dev -y;
                  git clone https://github.com/pc84560895/FYP-Scripts;
                  find ~/FYP-Scripts/*.sh -type f -exec chmod +x {} \;\n
                  find ~/FYP-Scripts/*.py -type f -exec chmod +x {} \;\n
                  cd FYP-Scripts/;
                  echo '{}' | sudo -S {}
                  echo '{}' | sudo -S chmod 777 ~/HOSTTools/nmap/
                  '''.format(request.POST["password"],request.POST["password"],request.POST["password"],'{}', '{}',request.POST["password"],'./honeypotprerequisites.sh' if servertype == 'honeypots' else './scannerprerequisites.sh', request.POST["password"])
        executeSSHbuffered(client, command, 'loading.txt', False)


        client.close()
        return True
    except Exception as e:
       print("fail to connect " + str(e))
       return False

#Display out loading text when installing/editing server
def loadingtext(request):
    lines=''
    try:
        with open('loading.txt', 'r') as f:
            for s in f.readlines():
                lines += s
    except Exception:
        pass
    jsondict = {'lines':lines}

    return HttpResponse(json.dumps(jsondict), content_type='application/json')
