from honeypot.models import Honeypot, Deployment
from django.conf import settings
from main.lib import *
import re
import requests

# Description: Get all honeypot types and order them by default first
# Parameters: nil
# Return: Honeypots <list>
def getAllHoneypots():
    honeypots = Honeypot.objects.all().order_by('-default')
    return honeypots

# Description: Get SSH Client for deployment
# Parameters: deployment_id <string, int>
# Return: sshClient <Object>
def getDeploymentSSH(deployment_id):
    sshClient = None

    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        sshCred = deployment.sshCred
        ip = sshCred.ip
        port = sshCred.port
        username = sshCred.username
        password = sshCred.password

        sshClient = connectSSH(ip,port,username,password)

    return sshClient

# Description: SSH into system and build deployment
# Parameters: deployment_id <string, int>
# Return: data <string> -> SSH Output
def buildDeploymentSSH(deployment_id):
    data = ''

    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        honeypot = deployment.honeypot
        sshCred = deployment.sshCred
        if honeypot and sshCred:
            sshClient = getDeploymentSSH(deployment_id)
            if sshClient:
                deployment_folder = deploymentFolder(deployment_id)

                deployment_log_volume = deploymentLogVolume(deployment_id)
                deployment_binaries_volume = deploymentBinariesVolume(deployment_id)

                git_folder = '{}_Git/'.format(deployment_folder)

                logpath = honeypot.log_path
                portmappings = honeypot.port_mappings
                imagename = honeypot.imagename
                giturl = honeypot.giturl
                folder = honeypot.folder
                gendockerscript = honeypot.generatescript
                binariespath = honeypot.binaries_path
                script = honeypot.script

                portmappings = formatPortMappings(portmappings)
                if portmappings:
                    parameters = {
                        'deployment_id': deployment_id,
                        'honeypot_name': honeypot.name,
                        'giturl': giturl,
                        'log_folder': settings.LOG_FOLDER,
                        'git_folder': git_folder,
                        'logpath': logpath,
                        'binariespath': binariespath,
                        'deployment_log_volume': deployment_log_volume,
                        'deployment_binaries_volume': deployment_binaries_volume
                    }

                    cleanup_cmd = 'rm -rf {git_folder};'.format(**parameters)

                    # Remove git folder if exist
                    command = cleanup_cmd

                    if giturl:
                        # Clone into git folder
                        command += 'git clone {giturl} {git_folder} && cd {git_folder};'.format(**parameters)

                        if not folder or not isPathSafe(folder):
                            folder = '.'
                    else:
                        # Change if using "<FYP-Scripts>" prefix
                        if folder.startswith('<FYP-Scripts>'):
                            folder = folder.replace('<FYP-Scripts>', '~/FYP-Scripts', 1)

                    if folder:
                        # Navigate to folder
                        command += 'cd {};'.format(folder)

                        # Give execute permission to file and execute it
                        if gendockerscript and isPathSafe(gendockerscript):
                            command += 'chmod +x {} && ./{};'.format(gendockerscript, gendockerscript)

                        if not imagename:
                            # Give image name if not given
                            imagename = 'deployment-{deployment_id}-{honeypot_name}'.format(**parameters).replace(' ','-').lower()

                        # Build docker
                        command += 'docker build -t {} .;'.format(imagename)

                    if imagename:
                        # Create build log
                        filename = '{log_folder}/deployment_{deployment_id}_build.log'.format(**parameters)
                        dirname = os.path.dirname(filename)
                        if dirname != '' and not os.path.isdir(dirname):
                            # Create parent directories it does not exist
                            os.makedirs(dirname)

                        # Execute SSH in buffered mode
                        jsondata = executeSSHbufferedJson(sshClient, command, filename, False)

                        # Setup parameters for mounts
                        volumes = [deployment_log_volume]
                        mountparam = '-v {deployment_log_volume}:{logpath}'.format(**parameters)
                        if binariespath:
                            # Binaries mount
                            mountparam += ' -v {deployment_binaries_volume}:{binariespath}'.format(**parameters)
                            volumes.append(deployment_binaries_volume)

                        # Run docker command
                        runcmd = 'docker run -d {} {} {}'.format(mountparam, portmappings, imagename)
                        if script:
                            # Add script to run inside docker if any
                            runcmd = '{} {} -d'.format(runcmd, script)

                        parameters['runcmd'] = runcmd

                        command = ''
                        for v in volumes:
                            p = {
                                'volume': v,
                                'volume_folder': getVolumeDataPath(v)
                            }

                            # Create volumes and make it world readable as some dockers are not running as root
                            command += 'docker volume create {volume} && chmod 777 {volume_folder};'.format(**p)

                        # Execute run command
                        command += '{runcmd};'.format(**parameters)
                        result = executeSSH(sshClient,command)
                        data = ''.join(result['output'])
                        error = ''.join(result['error'])

                        # Set finish
                        with open(filename, 'w') as f:
                            jsondata['Output'] += data
                            jsondata['Error'] += error
                            jsondata['Finish'] = True
                            json.dump(jsondata, f)

                        # Clean up
                        command = cleanup_cmd
                        executeSSH(sshClient, command)

                sshClient.close()

    return data

# Description: Start Docker
# Parameters: deployment_id <string, int>
# Return: nil
def startDocker(deployment_id):
    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        docker_id = deployment.docker_id

        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            try:
                command = 'docker start {}'.format(docker_id)
                executeSSH(sshClient, command)
            except:
                pass

            sshClient.close()

# Description: Stop Docker
# Parameters: deployment_id <string, int>
# Return: nil
def stopDocker(deployment_id):
    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        docker_id = deployment.docker_id

        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            try:
                command = 'docker stop {}'.format(docker_id)
                executeSSH(sshClient, command)
            except:
                pass

            sshClient.close()

# Description: Get Docker status
# Parameters: deployment_id <string, int>
# Return: status <int> -> 0 = Error, 1 = Running, 2 = Exited, 3 = Build required, 4 = Building
def getDockerStatus(deployment_id):
    status = 0

    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            dockerid = deployment.docker_id
            if dockerid:
                try:
                    command = 'docker inspect --format="{{.State.Status}}" %s' % (dockerid)
                    result = executeSSH(sshClient,command)
                    output = ''.join(result['output']).strip()
                    if output == 'running':
                        status = 1
                    elif output == 'exited':
                        status = 2
                except:
                    pass
            else:
                filename = buildlogFilename(deployment_id)
                if fileExists(filename):
                    json = readFileJson(filename)
                    if 'Finish' in json and not json['Finish']:
                        status = 4
                else:
                    if isHoneypotBuildable(deployment.honeypot_id):
                        status = 3

            sshClient.close()

    return status

# Description: Check if honeypot is buildable
# Parameters: honeypot_id <string, int>
# Return: buildable <bool> -> True = buildable, False = not buildable
def isHoneypotBuildable(honeypot_id):
    buildable = False

    honeypot = Honeypot.objects.get(id=honeypot_id)
    if honeypot:
        if honeypot.imagename or honeypot.giturl:
            buildable = True

    return buildable

# Description: Get deployment folder path (For Git)
# Parameters: deployment_id <string, int>
# Return: deployment_folder <string>
def deploymentFolder(deployment_id):
    remote_folder = '~/{}/Honeypots/Dockers'.format(settings.REMOTE_FOLDER)
    deployment_folder = '{}/Deployment_{}'.format(remote_folder, deployment_id)

    return deployment_folder

# Description: Get docker volume path
# Parameters: volume <string>
# Return: path <string>
def getVolumeDataPath(volume):
    path = '/var/lib/docker/volumes/{}/_data'.format(volume)

    return path

# Description: Get deployment log volume name
# Parameters: deployment_id <string, int>
# Return: volume <string>
def deploymentLogVolume(deployment_id):
    volume = 'Deployment_{}_Logs'.format(deployment_id)
    return volume

# Description: Get deployment log volume path
# Parameters: deployment_id <string, int>
# Return: path <string>
def deploymentLogVolumeFolder(deployment_id):
    deployment = Deployment.objects.get(id=deployment_id)
    if deployment and deployment.mountvolume:
        volume = deployment.mountvolume
    else:
        # No mountvolume, determine volume name instead
        volume = deploymentLogVolume(deployment_id)

    path = getVolumeDataPath(volume)

    return path

# Description: Get deployment binaries volume name
# Parameters: deployment_id <string, int>
# Return: volume <string>
def deploymentBinariesVolume(deployment_id):
    volume = 'Deployment_{}_Binaries'.format(deployment_id)
    return volume

# Description: Get deployment binaries volume path
# Parameters: deployment_id <string, int>
# Return: path <string>
def deploymentBinariesVolumeFolder(deployment_id):
    deployment = Deployment.objects.get(id=deployment_id)
    if deployment and deployment.binariesvolume:
        volume = deployment.binariesvolume
    else:
        volume = deploymentBinariesVolume(deployment_id)

    path = getVolumeDataPath(volume)

    return path

# Description: SSH into system and list log files
# Parameters: deployment_id <string, int>, type <int> -> 1 = Log, 2 = Binaries
# Return: path <string>
def getLogs(deployment_id, type=1):
    files = []

    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        honeypot = deployment.honeypot

        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            pattern = None
            if type == 1:
                # Normal logs
                log_volume_folder = deploymentLogVolumeFolder(deployment_id)
                pattern = honeypot.log_pattern
            else:
                # Binaries
                log_volume_folder = deploymentBinariesVolumeFolder(deployment_id)

            if not pattern:
                # If no pattern provided, assume all files are logs
                pattern = '.*'

            # List files with size in MB
            command = 'cd {} && ls -pl --block-size=MB | grep -v /'.format(log_volume_folder)
            result = executeSSH(sshClient, command)
            output = result['output']

            # Filter files if needed
            for line in output:
                parts = re.split(r'\s+',line)
                if len(parts) >= 9:
                    filename = ' '.join(parts[8:]).strip()
                    size = parts[4].strip()

                    if re.match(pattern,filename):
                        files.append({
                            'filename': filename,
                            'size': size
                        })

            sshClient.close()

    return files

# Description: Read Log file
# Parameters: deployment_id <string, int>, filename <string>
# Return: output <string>
def readLog(deployment_id, filename):
    output = ''

    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            log_volume_folder = deploymentLogVolumeFolder(deployment_id)

            parameters = {
                'log_volume_folder': log_volume_folder,
                'filename': filename
            }

            filename = '{log_volume_folder}/{filename}'.format(**parameters)
            output = readServerFile(sshClient, filename)

            sshClient.close()

    return output

# Description: Download Log file
# Parameters: deployment_id <string, int>, filename <string>, type <int> -> 1 = Log, 2 = Binaries
# Return: local_path <string> -> Path of downloaded file relative to project root
def downloadLog(deployment_id, filename, type=1):
    local_path = ''

    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            if type == 1:
                # Normal logs
                log_volume_folder = deploymentLogVolumeFolder(deployment_id)
            else:
                # Binaries
                log_volume_folder = deploymentBinariesVolumeFolder(deployment_id)

            # Unique filename for downloaded file (local)
            filename_local = hashSHA256('{}_{}_{}'.format(deployment_id,filename,getTimestamp()))

            # Create temp folder if does not exist
            tempfolder = settings.TEMP_FOLDER
            if not os.path.isdir(tempfolder):
                os.makedirs(tempfolder)

            parameters = {
                'filename_local': filename_local,
                'log_volume_folder': log_volume_folder,
                'filename': filename,
                'temp_folder': tempfolder
            }

            # Download file
            remote_path = '{log_volume_folder}/{filename}'.format(**parameters)
            local_path = '{temp_folder}/{filename_local}'.format(**parameters)
            downloadServerFile(sshClient,remote_path,local_path)

    return local_path

# Description: Get build log filename (local)
# Parameters: deployment_id <string, int>
# Return: path <string> -> Path of build log file relative to project root
def buildlogFilename(deployment_id):
    parameters = {
        'log_folder': settings.LOG_FOLDER,
        'deployment_id': deployment_id
    }

    return '{log_folder}/deployment_{deployment_id}_build.log'.format(**parameters)

# Description: Get port mappings
# Parameters: deployment_id <string, int>
# Return: results <dict> -> Key = dockerport
def getPortMappings(deployment_id):
    results = {}

    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        dockerid = deployment.docker_id
        if dockerid:
            sshClient = getDeploymentSSH(deployment_id)
            if sshClient:
                command = 'docker port {}'.format(dockerid)
                result = executeSSH(sshClient,command)
                output = result['output']
                if output:
                    p = r'(?P<dockerport>(\d+))\/(?P<protocol>(\w+)) -> \d+\.\d+\.\d+\.\d+:(?P<port>(\d+))'
                    for line in output:
                        line = line.strip()
                        search = re.search(p,line)
                        if search:
                            dockerport = search.group('dockerport')
                            protocol = search.group('protocol')
                            port = search.group('port')

                            results[dockerport] = {
                                'port': port,
                                'protocol': protocol
                            }

    return results

# Description: Monitor file (Splunk)
# Parameters: deployment_id <string, int>, filename <string>
# Return: nil
def addMonitorFile(deployment_id,filename):
    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            log_volume_folder = deploymentLogVolumeFolder(deployment_id)
            filepath = '{}/{}'.format(log_volume_folder, filename)

            parameters = {
                'filename': filename,
                'filepath': filepath
            }

            command = getSplunkCommand('add monitor {filepath} -index main -sourcetype {filename}'.format(**parameters))
            executeSSH(sshClient, command)

# Description: Unmonitor file (Splunk)
# Parameters: deployment_id <string, int>, filename <string>
# Return: nil
def removeMonitorFile(deployment_id,filename):
    deployment = Deployment.objects.get(id=deployment_id)
    if deployment:
        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            log_volume_folder = deploymentLogVolumeFolder(deployment_id)
            filepath = '{}/{}'.format(log_volume_folder,filename)

            parameters = {
                'filename': filename,
                'filepath': filepath
            }

            command = getSplunkCommand('remove monitor {filepath} -index main -sourcetype {filename}'.format(**parameters))
            executeSSH(sshClient, command)

# Description: Get monitored files (Splunk)
# Parameters: deployment_id <string, int>
# Return: files <list>
def getMonitoredFiles(deployment_id):
    deployment = Deployment.objects.get(id=deployment_id)

    files = []

    if deployment:
        logvolume = deploymentLogVolumeFolder(deployment_id)
        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            command = getSplunkCommand('list monitor')
            result = executeSSH(sshClient,command)
            output = result['output']
            try:
                index = output.index('Monitored Files:\n')
                array = output[(index + 1):]
                for a in array:
                    if a.startswith('\t'):
                        a = a.strip()
                        f = os.path.basename(a)

                        check = '{}/{}'.format(logvolume,f)
                        if a == check:
                            files.append(f)
            except:
                pass

    return files

# Description: Get monitored folders (Splunk)
# Parameters: deployment_id <string, int>
# Return: folders <list>
def getMonitoredFolders(deployment_id):
    deployment = Deployment.objects.get(id=deployment_id)

    folders = {}

    if deployment:
        sshClient = getDeploymentSSH(deployment_id)
        if sshClient:
            command = getSplunkCommand('list monitor')
            result = executeSSH(sshClient,command)
            output = result['output']
            try:
                index = output.index('Monitored Files:\n')
                array = output[:index][1:]

                cur = None
                for a in array:
                    if re.match(r'^\t([^\t]+)',a):
                        cur = a
                        folders[cur] = []
                    elif re.match(r'^\t\t(.*)',a):
                        if cur:
                            arr = folders[cur]
                            arr.append(a)
                            folders[cur] = arr
            except:
                pass

    return folders

# Description: Format port mappings
# Parameters: string <string>
# Return: mapping <list> -> Port mapping in '-p' format
def formatPortMappings(string):
    mapping = []

    string = string.lower()

    pattern = r'((\d+\.\d+\.\d+\.\d+:)?\d+:\d+(/(tcp|udp))?)'
    parts = string.split(',')
    for p in parts:
        p = p.strip()
        search = re.search(pattern,p)
        if search:
            p = '{} '.format(search.group(1))
            mapping.append('-p {}'.format(p))

    return ' '.join(mapping)

# Description: Common function to get splunk command with all neccessary args
# Parameters: arg <string>
# Return: command <string>
def getSplunkCommand(arg):
    command = '/opt/splunkforwarder/bin/splunk {} -auth \'admin:changeme\' --accept-license --answer-yes'.format(arg)
    return command

# Description: Upload file to VirusTotal
# Parameters: file <string> -> Relative to project root
# Return: json_response -> Response from VirusTotal
def uploadToVT(file):
    apikey = settings.VIRUSTOTAL_APIKEY
    params = {'apikey': apikey}

    filaname = os.path.basename(file)
    files = {'file': (filaname, open(file, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    json_response = response.json()

    return json_response