import paramiko, re, os, json, hashlib, datetime

#Common function use throughout the code to do SSH connections to the server using paramiko.
def connectSSH(ip,port,username,passsword):
    sshClient = None
    try:
        sshClient = paramiko.SSHClient()
        sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshClient.load_system_host_keys()
        sshClient.connect(hostname=ip,port=port,username=username,password=passsword)
    except:
        pass

    return sshClient

#Common function use to execute SSH commands on the server using paramiko after SSH connection is established.
def executeSSH(sshClient,command):
    stdin, stdout, stderr = sshClient.exec_command(command)
    result = {
        'output': stdout.readlines(),
        'error': stderr.readlines()
    }

    return result

#Converts ‘line’ gotten from stdout into utf-8 format
def line_buffered(f):
    line_buf = ''
    while not f.channel.exit_status_ready():
        line_buf += f.read(1).decode('utf-8')
        if line_buf.endswith('\n'):
            yield line_buf
            line_buf = ''

#Execute SSH functions and running line_buffered function to write a ‘line’ to a file for display.
def executeSSHbuffered(sshClient,command,filename,append=True,clean=True):
    if clean and os.path.isfile(filename):
        os.remove(filename)

    if append:
        mode = 'a'
    else:
        mode = 'w'

    stdin, stdout, stderr = sshClient.exec_command(command)
    for line in line_buffered(stdout):
        with open(filename,mode) as f:
            f.write(line)

#Similar to executeSSHbuffered, except the data is saved in JSON.
def executeSSHbufferedJson(sshClient,command,filename,finish=True,append=True,clean=True):
    if clean and os.path.isfile(filename):
        os.remove(filename)

    stdin, stdout, stderr = sshClient.exec_command(command)

    data = {
        'Output': '',
        'Error': '',
        'Finish': False
    }

    for line in line_buffered(stdout):
        with open(filename,'w') as f:
            output = data['Output']

            if append:
                output += line
            else:
                output = line

            data['Output'] = output
            json.dump(data, f)

    with open(filename, 'w') as f:
        errors = stderr.readlines()
        for i,line in enumerate(errors):
            line = line.strip()
            if re.search(r'^Cloning into \'.*\'\.\.\.',line):
                del errors[i]

        errors = ''.join(errors)

        data['Error'] = errors

        if finish:
            data['Finish'] = True

        json.dump(data, f)

    return data

#Read JSON from file
def readFileJson(filename):
    data = {}

    try:
        with open(filename,'r') as f:
            data = json.load(f)
    except:
        pass

    return data

#Used in readLog function in honeypot lib.py. Does an SFTP connection and open the log file to read the log file.
def readServerFile(sshClient,filename):
    data = ''

    if filename[:2] == '~/':
        filename = filename[2:]

    try:
        transport = sshClient.get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)
        with sftp.open(filename,'r') as f:
            for line in f:
                data += line
    except:
        pass

    return data

def downloadServerFile(sshClient,remote_path,local_path):
    try:
        transport = sshClient.get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.get(remote_path,local_path)
    except:
        pass

def putServerFile(sshClient, remote_path,local_path):
    try:
        transport = sshClient.get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(local_path, remote_path)
    except:
        pass

def getKeyValue(dict,key,default=None):
    value = default
    if key in dict:
        value = dict[key]

    return value

def getPostValue(request,key,default=''):
    return getKeyValue(request.POST,key,default)

def fileExists(filename):
    return os.path.isfile(filename)

def deleteFile(filename):
    if filename and fileExists(filename):
        os.remove(filename)

def getFilenameFromPath(path):
    return os.path.basename(path)

def getDirFromPath(path):
    return os.path.dirname(path)

def hashSHA256(message):
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

def getTimestamp():
    timestamp = datetime.datetime.now().isoformat()
    return timestamp

def isPathSafe(path):
    safe = False
    if not path.startswith('~') and ';' not in path and '&&' not in path and not path.startswith('/') and not re.match(r'\.\.',path) and not re.match(r'cd\s+',path):
        safe = True

    return safe