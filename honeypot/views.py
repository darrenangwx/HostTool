from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.urls import reverse
from main.models import SSHCred
from servermanager.views import sshjson
from honeypot.lib import *
import json

# Create your views here.

# /honeypot/
def honeypotindex(request):
    return render(request, 'honeypot/honeypot.html')

# /honeypot/json/<honeypot_id>/
def honeypotjson(request,honeypot_id=None):
    results = []

    if honeypot_id:
        honeypots = Honeypot.objects.filter(id=honeypot_id)
    else:
        honeypots = getAllHoneypots()

    for honeypot in honeypots:
        results.append({
            'ID': honeypot.id,
            'Name': honeypot.name,
            'Logpath': honeypot.log_path,
            'Imagename': honeypot.imagename,
            'Portmappings': honeypot.port_mappings,
            'Giturl': honeypot.giturl,
            'Folder': honeypot.folder,
            'Gendockerscript': honeypot.generatescript,
            'Logpattern': honeypot.log_pattern,
            'Binariespath': honeypot.binaries_path,
            'Script': honeypot.script,
            'Default': honeypot.default
        })

    return HttpResponse(json.dumps(results), content_type='application/json')

# /honeypot/table/
def honeypot_table(request):
    honeypots = getAllHoneypots()

    results = []

    for h in honeypots:
        honeypot_id = h.id
        name = h.name
        default = h.default

        parameters = {
            'honeypot_id': honeypot_id,
            'name': name,
            'deleteurl': ''
        }

        if default:
            name = '<span class="label label-primary">Default</span> {}'.format(name)
            deletebtn_attr = 'disabled'
            actionsbtn_attr = 'onclick="addModal_open({honeypot_id},true)"'.format(**parameters)
            actionsbtn_icon = 'glyphicon glyphicon-eye-open'
            actionsbtn_text = 'View'
        else:
            parameters['deleteurl'] = reverse(deletehoneypot, kwargs={'honeypot_id': honeypot_id})

            deletebtn_attr = 'onclick="showConfirmModal(\'{honeypot_id}\',\'{name}\',\'{deleteurl}\')"'.format(**parameters)
            actionsbtn_attr = 'onclick="addModal_open({honeypot_id})"'.format(**parameters)
            actionsbtn_icon = 'glyphicon glyphicon-edit'
            actionsbtn_text = 'Edit'

        log_path = h.log_path
        if not log_path:
            log_path = '-'

        binaries_path = h.binaries_path
        if not binaries_path:
            binaries_path = '-'

        parameters['deletebtn_attr'] = deletebtn_attr
        parameters['actionsbtn_attr'] = actionsbtn_attr
        parameters['actionsbtn_icon'] = actionsbtn_icon
        parameters['actionsbtn_text'] = actionsbtn_text

        delete = """
            <button type="button" class="btn btn-link btn-sm icon_colororangered" {deletebtn_attr}><span class="glyphicon glyphicon-remove-circle"></span></button>
        """.format(**parameters)

        actions = """
            <button type="button" class="btn btn-default btn-sm fullwidth" {actionsbtn_attr}><span class="{actionsbtn_icon}"></span> {actionsbtn_text}</button>
        """.format(**parameters)

        results.append({
            '0': honeypot_id,
            '1': delete,
            '2': name,
            '3': log_path,
            '4': binaries_path,
            '5': actions
        })

    return HttpResponse(json.dumps(results), content_type='application/json')

# /honeypot/add/
def addhoneypot(request):
    if request.method == 'POST':
        name = getPostValue(request, 'name')
        logpath = getPostValue(request, 'logpath')
        imagename = getPostValue(request, 'imagename')
        portmappings = getPostValue(request, 'portmappings')
        giturl = getPostValue(request, 'giturl')
        folder = getPostValue(request, 'folder')
        gendockerscript = getPostValue(request, 'gendockerscript')
        logpattern = getPostValue(request, 'logpattern')
        binariespath = getPostValue(request, 'binariespath')
        script = getPostValue(request, 'script')

        honeypot = Honeypot()
        honeypot.name = name
        honeypot.log_path = logpath
        honeypot.imagename = imagename
        honeypot.port_mappings = portmappings
        honeypot.giturl = giturl
        honeypot.folder = folder
        honeypot.generatescript = gendockerscript
        honeypot.log_pattern = logpattern
        honeypot.binaries_path = binariespath
        honeypot.script = script
        honeypot.save()

    return redirect(honeypotindex)

# /honeypot/delete/<honeypot_id>/
def deletehoneypot(request,honeypot_id):
    honeypot = get_object_or_404(Honeypot,id=honeypot_id)
    if honeypot:
        if not honeypot.default:
            honeypot.delete()

    return redirect(honeypotindex)

# /honeypot/edit/
def edithoneypot(request):
    if request.method == 'POST':
        id = getPostValue(request,'id')
        honeypot = get_object_or_404(Honeypot,id=id)
        if honeypot:
            if not honeypot.default:
                name = getPostValue(request, 'name')
                logpath = getPostValue(request, 'logpath')
                imagename = getPostValue(request, 'imagename')
                portmappings = getPostValue(request, 'portmappings')
                giturl = getPostValue(request, 'giturl')
                folder = getPostValue(request, 'folder')
                gendockerscript = getPostValue(request, 'gendockerscript')
                logpattern = getPostValue(request, 'logpattern')
                binariespath = getPostValue(request, 'binariespath')
                script = getPostValue(request, 'script')

                honeypot.name = name
                honeypot.log_path = logpath
                honeypot.imagename = imagename
                honeypot.port_mappings = portmappings
                honeypot.giturl = giturl
                honeypot.folder = folder
                honeypot.generatescript = gendockerscript
                honeypot.log_pattern = logpattern
                honeypot.binaries_path = binariespath
                honeypot.script = script
                honeypot.save()

    return redirect(honeypotindex)

# /honeypot/deploy/
def deployhoneypot(request):
    return render(request, 'honeypot/deployment.html')

def deploymentjson(request,deployment_id=None):
    results = []

    if deployment_id:
        deployments = Deployment.objects.filter(id=deployment_id)
    else:
        deployments = Deployment.objects.all()

    for deployment in deployments:
        results.append({
            'ID': deployment.id,
            'honeypot_id': deployment.honeypot_id,
            'sshCred_id': deployment.sshCred_id,
            'docker_id': deployment.docker_id,
            'build': deployment.build,
            'mountvolume': deployment.mountvolume,
            'binariesvolume': deployment.binariesvolume
        })

    return HttpResponse(json.dumps(results), content_type='application/json')

# /honeypot/deploy/table/
def deployment_table(request):
    deployments = Deployment.objects.all()

    results = []

    for d in deployments:
        deployment_id = d.id
        honeypot = d.honeypot
        sshCred = d.sshCred
        dockerid = d.docker_id

        name = str(d)
        deleteurl = reverse(deploymentdelete,kwargs={'deployment_id': deployment_id})

        parameters = {
            'deployment_id': deployment_id,
            'name': name,
            'deleteurl': deleteurl,
            'dockerid': '',
            'binariesvolume': d.binariesvolume,
            'logvolume': d.mountvolume,
            'buildlog_attr': '',
            'copylog_attr': ''
        }

        delete = '''
            <button type="button" class="btn btn-link btn-sm icon_colororangered" onclick="showConfirmModal('{deployment_id}','{name}','{deleteurl}')"><span class="glyphicon glyphicon-remove-circle"></span></button>
        '''.format(**parameters)

        status = '''
            <div id="deployment_{deployment_id}_status"></div>
        '''.format(**parameters)

        actions = '''
            <div id="deployment_{deployment_id}_actions">
                <div class="btn-group btn-group-sm flexdisplay">
                    <button type="button" class="btn btn-default" onclick="startDocker(this,{deployment_id})" data-toggle="tooltip" title="Start" disabled><span class="glyphicon glyphicon-play icon_colorgreen"></span></button>
                    <button type="button" class="btn btn-default" onclick="stopDocker(this,{deployment_id})" data-toggle="tooltip" title="Stop" disabled><span class="glyphicon glyphicon-stop icon_colorred"></span></button>
                </div>
            </div>
        '''.format(**parameters)

        logs = '''
            <div id="deployment_{deployment_id}_logs" data-binariesvolume="{binariesvolume}" data-logvolume="{logvolume}">
                <div class="btn-group btn-group-sm flexdisplay">
                    <button type="button" class="btn btn-default" onclick="logsModal_open(this,{deployment_id},'{name}',2)" data-toggle="tooltip" title="Binaries" disabled><i class="fa fa-database" aria-hidden="true"></i>
                    <button type="button" class="btn btn-default" onclick="logsModal_open(this,{deployment_id},'{name}',1)" data-toggle="tooltip" title="Logs" disabled><i class="fa fa-folder icon_colorsteelblue" aria-hidden="true"></i></button>
                </div>
            </div>
        '''.format(**parameters)

        filename = buildlogFilename(deployment_id)
        buildlog_attr = 'onclick="openBuildModal(this,{deployment_id})"'.format(**parameters)
        if not fileExists(filename):
            buildlog_attr += ' disabled'

        parameters['buildlog_attr'] = buildlog_attr

        copylog_attr = 'data-clipboard-action="copy" data-clipboard-target="#deployment_{deployment_id}_input"'.format(**parameters)
        if not dockerid:
            dockerid = '-'
            copylog_attr += ' disabled'

        parameters['dockerid'] = dockerid
        parameters['copylog_attr'] = copylog_attr

        dockerid = '''
            <div class="input-group" id="deployment_{deployment_id}_inputgroup">
                <input type="text" class="form-control input-sm" value="{dockerid}" id="deployment_{deployment_id}_input" readonly>
                <span class="input-group-btn">
                    <div class="btn-group btn-group-sm flexdisplay">
                        <button class="btn btn-default buildlogbtn" type="button" data-toggle="tooltip" title="Build Log" {buildlog_attr}><i class="fa fa-file-text-o" aria-hidden="true"></i></button>
                        <button class="btn btn-default copybtn" type="button" data-toggle="tooltip" title="Copy" {copylog_attr}><i class="fa fa-files-o" aria-hidden="true"></i></button>
                    </div>
                </span>
            </div>
        '''.format(**parameters)

        sshCred = '''
            <button class="btn btn-default btn-sm" id="deployment_sshcred" type="button" data-toggle="tooltip" title="{}@{}"><i class="fa fa-server" aria-hidden="true"></i> {}</button>
        '''.format(sshCred.username,sshCred.ip,sshCred.name)

        results.append({
            '0': deployment_id,
            '1': delete,
            '2': honeypot.name,
            '3': sshCred,
            '4': dockerid,
            '5': status,
            '6': actions,
            '7': logs,
            'server': d.sshCred.name,
            'dockerid': d.docker_id
        })

    return HttpResponse(json.dumps(results), content_type='application/json')

# /honeypot/deploy/add/
def deploymentadd(request):
    if request.method == 'POST':
        honeypot_id = getPostValue(request,'honeypot')
        sshCred_id = getPostValue(request,'server')
        dockerid = getPostValue(request,'dockerid')
        mountvolume = getPostValue(request,'mountvolume')
        binariesvolume = getPostValue(request,'binariesvolume')

        if honeypot_id and sshCred_id:
            honeypot = get_object_or_404(Honeypot,id=honeypot_id)
            sshCred = get_object_or_404(SSHCred,id=sshCred_id)
            if honeypot and sshCred:
                deployment = Deployment()
                deployment.honeypot = honeypot
                deployment.sshCred = sshCred
                deployment.docker_id = dockerid
                deployment.mountvolume = mountvolume
                deployment.binariesvolume = binariesvolume
                deployment.save()

    return redirect(deployhoneypot)

# /honeypot/deploy/add/json/
def deploymentaddjson(request):
    honeypots = json.loads(honeypotjson(request).getvalue().decode('utf8'))
    sshCreds = json.loads(sshjson(request,type='honeypots').getvalue().decode('utf8'))

    results = {
        'Honeypots': honeypots,
        'SSHCreds': sshCreds
    }

    return HttpResponse(json.dumps(results), content_type='application/json')

# /honeypot/deploy/build/<deployment_id>/
def deploymentbuild(request,deployment_id):
    deployment = get_object_or_404(Deployment,id=deployment_id)
    if deployment:
        if not deployment.build:
            deployment.build = True
            deployment.save()

            if not deployment.docker_id:
                data = buildDeploymentSSH(deployment_id)
                output = data.split('\n')
                if len(output) >= 2:
                    deployment_log_volume = deploymentLogVolume(deployment_id)
                    deployment_binaries_volume = deploymentBinariesVolume(deployment_id)

                    dockerid = output[-2].strip()
                    if re.match(r'^[a-zA-Z0-9]+$',dockerid):
                        deployment.docker_id = dockerid
                        deployment.mountvolume = deployment_log_volume
                        deployment.binariesvolume = deployment_binaries_volume
                        deployment.save()

    return HttpResponse('')

# /honeypot/deploy/build/<deployment_id>/progress/
def deploymentbuildprogress(request,deployment_id):
    result = {}

    deployment = get_object_or_404(Deployment,id=deployment_id)
    if deployment:
        filename = buildlogFilename(deployment_id)
        if filename:
            result = readFileJson(filename)

    return HttpResponse(json.dumps(result), content_type='application/json')

# /honeypot/deploy/build/<deployment_id>/progress/delete/
def deploymentbuildprogressdelete(request,deployment_id):
    deployment = get_object_or_404(Deployment,id=deployment_id)
    if deployment:
        filename = buildlogFilename(deployment_id)
        if filename:
            deleteFile(filename)

    return HttpResponse('')

# /honeypot/deploy/delete/<deployment_id>/
def deploymentdelete(request, deployment_id):
    deployment = get_object_or_404(Deployment,id=deployment_id)
    if deployment:
        deployment.delete()

    return redirect(deployhoneypot)

# /honeypot/deploy/start/<deployment_id>/
def deploymentstart(request, deployment_id):
    startDocker(deployment_id)

    return HttpResponse('')

# /honeypot/deploy/stop/<deployment_id>/
def deploymentstop(request, deployment_id):
    stopDocker(deployment_id)

    return HttpResponse('')

# /honeypot/deploy/status/<deployment_id>/
def deploymentstatus(request, deployment_id):
    status = getDockerStatus(deployment_id)
    results = {"Status":status}

    return HttpResponse(json.dumps(results), content_type='application/json')

# /honeypot/deploy/logs/<deployment_id>/
def deploymentlogs(request, deployment_id):
    return HttpResponse('')

# /honeypot/deploy/logs/<deployment_id>/table/
def deploymentlogs_table(request, deployment_id):
    files = getLogs(deployment_id)

    result = []

    monitoredFiles = getMonitoredFiles(deployment_id)

    for i,f in enumerate(files):
        filename = f['filename']
        size = f['size']

        parameters = {
            'deployment_id': deployment_id,
            'filename': filename,
            'view_url': (reverse(deploymentlogview, kwargs={'deployment_id': deployment_id, 'filename': filename})),
            'download_url': (reverse(deploymentlogdownload, kwargs={'deployment_id': deployment_id, 'filename': filename}))
        }

        if filename in monitoredFiles:
            monitorbtn = '<button type="button" class="btn btn-default icon_colororangered" onclick="monitorAddRemove(this,{deployment_id},\'{filename}\',2)" data-toggle="tooltip" title="Unmonitor"><span class="glyphicon glyphicon-eye-close"></span></button>'.format(**parameters)
        else:
            monitorbtn = '<button type="button" class="btn btn-default icon_colorgreen" onclick="monitorAddRemove(this,{deployment_id},\'{filename}\',1)" data-toggle="tooltip" title="Monitor"><span class="glyphicon glyphicon-eye-open"></span></button>'.format(**parameters)

        parameters['monitor_button'] = monitorbtn

        action = '''
            <div class="btn-group btn-group-sm flexdisplay">
                {monitor_button}
                <button type="button" class="btn btn-default" onclick="openWindow(\'{download_url}\')" data-toggle="tooltip" title="Download"><span class="glyphicon glyphicon-download-alt"></span></button>
                <button type="button" class="btn btn-default icon_colorsteelblue" onclick="location.href=\'{view_url}\'" data-toggle="tooltip" title="View"><i class="fa fa-file-text-o"></i></button>
            </div>
        '''.format(**parameters)

        result.append({
            '0': (i + 1),
            '1': filename,
            '2': size,
            '3': action
        })

    return HttpResponse(json.dumps(result), content_type="application/json")

# /honeypot/deploy/logs/<deployment_id>/<filename>/
def deploymentlogview(request, deployment_id, filename):
    context = {
        'deployment_id': deployment_id,
        'heading': filename,
        'content': readLog(deployment_id, filename)
    }

    return render(request,'honeypot/log.html',context)

# /honeypot/deploy/logs/download/<deployment_id>/<filename>/
def deploymentlogdownload(request, deployment_id, filename):
    filepath = downloadLog(deployment_id,filename)

    response = HttpResponse()

    if (filepath):
        try:
            with open(filepath,"rb") as f:
                response = HttpResponse(f,content_type='application/force-download')
                response['Content-Disposition'] = 'attachment; filename={}'.format(filename)

            deleteFile(filepath)
        except:
            pass

    return response

# /honeypot/deploy/logs/addmonitor/<deployment_id>/<filename>/
def deploymentlogaddmonitor(request, deployment_id, filename):
    addMonitorFile(deployment_id,filename)

    return HttpResponse('')

# /honeypot/deploy/logs/removemonitor/<deployment_id>/<filename>/
def deploymentlogremovemonitor(request, deployment_id, filename):
    removeMonitorFile(deployment_id,filename)

    return HttpResponse('')

# /honeypot/deploy/binaries/<deployment_id>/
def deploymentbinaries(request, deployment_id):
    return HttpResponse('')

# /honeypot/deploy/binaries/<deployment_id>/table/
def deploymentbinaries_table(request, deployment_id):
    files = getLogs(deployment_id,2)

    result = []

    for i,f in enumerate(files):
        filename = f['filename']
        size = f['size']

        parameters = {
            'deployment_id': deployment_id,
            'filename': filename,
            'view_url': (reverse(deploymentlogview, kwargs={'deployment_id': deployment_id, 'filename': filename})),
            'download_url': (reverse(deploymentbinariesdownload, kwargs={'deployment_id': deployment_id, 'filename': filename})),
            'upload_url': (reverse(deploymentbinariesvt, kwargs={'deployment_id': deployment_id, 'filename': filename}))
        }

        action = '''
            <div class="btn-group btn-group-sm flexdisplay">
                <button type="button" class="btn btn-default" onclick="openWindow(\'{upload_url}\')" data-toggle="tooltip" title="Upload (VirusTotal)"><i class="fa fa-cloud-upload" aria-hidden="true"></i></button>
                <button type="button" class="btn btn-default" onclick="openWindow(\'{download_url}\')" data-toggle="tooltip" title="Download"><span class="glyphicon glyphicon-download-alt"></span></button>
            </div>
        '''.format(**parameters)

        result.append({
            '0': (i + 1),
            '1': filename,
            '2': size,
            '3': action
        })

    return HttpResponse(json.dumps(result), content_type="application/json")

# /honeypot/deploy/binaries/download/<deployment_id>/<filename>/
def deploymentbinariesdownload(request, deployment_id, filename):
    filepath = downloadLog(deployment_id,filename,2)

    response = HttpResponse()

    if (filepath):
        try:
            with open(filepath,"rb") as f:
                response = HttpResponse(f,content_type='application/force-download')
                response['Content-Disposition'] = 'attachment; filename={}'.format(filename)

            deleteFile(filepath)
        except:
            pass

    return response

# /honeypot/deploy/binaries/upload/<deployment_id>/<filename>/
def deploymentbinariesvt(request, deployment_id, filename):
    filepath = downloadLog(deployment_id, filename, 2)
    json_response = uploadToVT(filepath)

    deleteFile(filepath)

    url = json_response['permalink']
    return redirect(url)

# /honeypot/deploy/ports/<deployment_id>/
def deploymentports(request, deployment_id):
    result = getPortMappings(deployment_id)

    return HttpResponse(json.dumps(result), content_type="application/json")