import shutil
from django.shortcuts import render, redirect

from libnmap.parser import NmapParser

from main.models import SSHCred, ApiKey
import time
import os
from main.lib import connectSSH, downloadServerFile, executeSSH, putServerFile


# Create your views here.
#Return all the servers that have scanning type and all the xml files in scannerlogs folder to the network scanner page.
def index(request):
    serverip = SSHCred.objects.filter(servertype='scanning')
    scanhistory = sorted_ls(os.getcwd() + '/scannerlogs')

    list_timestamp = gettimestamp(scanhistory)


    context = {'serverip': serverip,
               'list_timestamp':list_timestamp}
    return render(request, 'scanner/networkscanner.html', context)

#Get all the parameters parsed from the form. String all the parameters into a masscan or nmap command line before sending it over to the server to execute it. After that, grab the scanned file from the server.
def startscan(request):
    if request.method == 'POST':

        server = request.POST['server']
        type = request.POST['type']
        speed = request.POST['speed']
        iprange = request.POST['iprange']
        scanningports = request.POST['scanningports']

        protocol = request.POST['protocol']

        ssh = SSHCred.objects.filter(ip=server)[0]
        sshpass = ssh.password
        serverport = ssh.port
        username = ssh.username


        sshClient = connectSSH(server, int(serverport), username, sshpass)


        if " " in iprange:
            iprange = iprange.strip(" ")

        if " " in scanningports:
            scanningports = scanningports.strip(" ")

        date = time.strftime("%Y.%m.%d")
        timing = time.strftime("%H.%M.%S")
        if type == 'nmap':
            try:
                name = "nmaplog_" + date+'_'+timing + '.xml'
                filename = 'HOSTTools/nmap/{}'.format(name)

                if scanningports == '':
                    command = '''
                            cd;
                            echo '{}' | sudo -S nmap -T4 -sSV -O -oX ~/HOSTTools/nmap/{} {} --top-ports 100 
                            '''.format(sshpass, name, iprange)

                    checkerror = executeSSH(sshClient,command)

                    if checkerror["error"]:
                        if "[sudo] password for" in checkerror['error'][0]:
                            downloadServerFile(sshClient, filename, 'scannerlogs/{}'.format(name))
                            sshClient.close()
                            return redirect(index)
                        error="error"
                        serverip = SSHCred.objects.filter(servertype='scanning')
                        scanhistory = sorted_ls(os.getcwd() + '/scannerlogs')
                        list_timestamp = gettimestamp(scanhistory)
                        context = {'serverip': serverip,
                                   'list_timestamp': list_timestamp,
                                   'error': error}
                        return render(request, 'scanner/networkscanner.html', context)

                else:
                    command = '''
                            cd;
                            echo '{}' | sudo -S nmap -T4 -sSV -O -oX ~/HOSTTools/nmap/{} {} -p {}
                            '''.format(sshpass, name, iprange, scanningports)
                    checkerror = executeSSH(sshClient, command)


                    if checkerror["error"]:
                        if "[sudo] password for" in checkerror['error'][0]:
                            downloadServerFile(sshClient, filename, 'scannerlogs/{}'.format(name))
                            sshClient.close()
                            return redirect(index)
                        error = "error"
                        serverip = SSHCred.objects.filter(servertype='scanning')
                        scanhistory = sorted_ls(os.getcwd() + '/scannerlogs')
                        list_timestamp = gettimestamp(scanhistory)
                        context = {'serverip': serverip,
                                   'list_timestamp': list_timestamp,
                                   'error': error}
                        return render(request, 'scanner/networkscanner.html', context)



                downloadServerFile(sshClient, filename, 'scannerlogs/{}'.format(name))

                sshClient.close()


            except Exception as e:
                print('An error has occured %s' % e)



        if type == 'masscan':

            try:
                if iprange == "":
                    iprange = "0.0.0.0/0"

                name = "masscanlog_" + date+'_'+timing + ".xml"
                filename = 'HOSTTools/masscan/{}'.format(name)

                if scanningports == '':
                    scanningports = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389," \
                                    "427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433," \
                                    "1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060," \
                                    "5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
                command = '''
                            cd;
                            echo '{}' | sudo -S masscan -oX ~/HOSTTools/masscan/{} {} -p {} --rate {} --excludefile ~/HOSTTools/masscan/data/exclude.conf
                            '''.format(sshpass, name, iprange, scanningports, speed)

                executeSSH(sshClient, command)

                downloadServerFile(sshClient, filename, 'scannerlogs/{}'.format(name))

                sshClient.close()
            except Exception as e:
                print('An error has occured %s' % e)

                return render(request,'scanner/networkscanner.html')

        return redirect(index)

#Go through the log files to filter out all the data such as hostname, open ports, ip address, etc.
def details(request, filename):
    if os.path.getsize('scannerlogs/' + filename) == 0:
        error = "error"
        context = {'error': error}
        return render(request, 'scanner/details.html', context)

    if "nmap" in filename:
        try:
            rep = NmapParser.parse_fromfile('scannerlogs/' + filename)

            list_host = []
            list_ip = []
            counter = []

            service = []
            state = []
            port = []
            banner = []
            osname = []

            count = 0
            counter.append(count)

            for host in rep.hosts:
                hostname = ', '.join(host.hostnames)
                ip = host.address
                list_host.append(hostname)
                list_ip.append(ip)

                list_os = []
                if host.os.osmatches:
                    for osmatch in host.os.osmatches:
                        osguess = osmatch.name + ' ---- ' + str(osmatch.accuracy) + '%'
                        list_os.append(osguess)
                else:
                    list_os.append("None")

                list_service = []
                list_state = []
                list_port = []
                list_banner = []
                for i in host.services:
                    list_service.append(i.service)
                    list_state.append(i.state)
                    list_port.append(i.port)
                    if i.banner:
                        list_banner.append(i.banner)
                    else:
                        list_banner.append("None")

                service.append(list_service)
                state.append(list_state)
                port.append(list_port)
                banner.append(list_banner)
                osname.append(list_os)

                count += 1
                counter.append(count)

            foo = zip(list_host, list_ip, osname, service, state, port, banner, counter)
            two = zip(service, state, port)

            type = "nmap"
            context = {'type': type,
                       'lists': foo,
                       'list': two}
            return render(request, 'scanner/details.html', context)

        except Exception as e:
            wrong = 'wrong'
            serverip = SSHCred.objects.filter(servertype='scanning')
            scanhistory = sorted_ls(os.getcwd() + '/scannerlogs')
            list_timestamp = gettimestamp(scanhistory)
            context = {'serverip': serverip,
                       'list_timestamp': list_timestamp,
                       'wrong': wrong}
            return render(request, 'scanner/networkscanner.html', context)

    else:
        try:

            rep = NmapParser.parse_fromfile('scannerlogs/' + filename)

            results = {}

            iplist = []
            iplist2 = []


            for host in rep.hosts:

                ip = host.address
                for i in host.services:
                    port = i.port

                if ip in results:
                    ports = results[ip]
                    ports.append(port)

                else:
                    ports = [port]

                if list:
                    ports.sort()
                    results[ip] = ports

                iplist.append(ip)

                for i in iplist:
                    if i not in iplist2:
                        iplist2.append(i)

            request.session['listofip'] = iplist2
            unique = []

            for key, value in results.items():
                for i in value:
                    if i not in unique:
                        unique.append(i)
                value = ', '.join(str(e) for e in value)
                results[key] = value

            request.session['listofports'] = unique

            serverip = SSHCred.objects.filter(servertype='scanning')
            type = "masscan"
            api_keys = ApiKey.objects.filter(type__type_name='Shodan')

            context = {'results': results,
                       'serverip': serverip,
                       'type': type,
                       'apikey': api_keys}
            return render(request, 'scanner/details.html', context)
        except Exception as e:
            wrong = 'wrong'
            serverip = SSHCred.objects.filter(servertype='scanning')
            scanhistory = sorted_ls(os.getcwd() + '/scannerlogs')
            list_timestamp = gettimestamp(scanhistory)
            context = {'serverip': serverip,
                       'list_timestamp': list_timestamp,
                       'wrong': wrong}
            return render(request, 'scanner/networkscanner.html', context)

#Sort the files in the folder according to data modified
def sorted_ls(path):
    mtime = lambda f: os.stat(os.path.join(path, f)).st_mtime
    return list(sorted(os.listdir(path), key=mtime))


#Get the list of IP address and ports from a Masscan file. The IP address will be stored into a text file and sent over to the server. A Nmap command will use the text file and ports to conduct a Nmap scan on the server.
def nmap_masscan(request):
    request.session.get('listofip')
    request.session.get('listofports')

    file = open("iplist.txt", "w+")
    for i in request.session.get('listofip'):
        file.write(i + " ")
    file.close()

    ip = ""
    for i in request.session.get('listofports'):
        ip += str(i) + ","

    if request.method == 'POST':
        server = request.POST['server']

    ssh = SSHCred.objects.filter(ip=server)[0]
    sshpass = ssh.password
    sshport = ssh.port
    sshusername = ssh.username


    sshClient = connectSSH(server, int(sshport), sshusername, sshpass)

    try:
        putServerFile(sshClient, 'HOSTTools/nmap/iplist.txt', 'iplist.txt')
    except:
        pass

    name = "nmap_masscan_" + time.strftime("%Y.%m.%d_%H.%M.%S") + '.xml'
    filename = 'HOSTTools/nmap/{}'.format(name)

    command = '''
    cd;
    echo '{}' | sudo -S nmap -T4 -sSV -O -Pn -oX ~/HOSTTools/nmap/{} -iL ~/HOSTTools/nmap/iplist.txt -p {}
    '''.format(sshpass, name, ip)

    checkerror = executeSSH(sshClient, command)

    if checkerror["error"]:
        if "[sudo] password for" in checkerror['error'][0]:
            downloadServerFile(sshClient, filename, 'scannerlogs/{}'.format(name))
            sshClient.close()
            return redirect(index)
        error = "error"
        serverip = SSHCred.objects.filter(servertype='scanning')
        scanhistory = sorted_ls(os.getcwd() + '/scannerlogs')
        list_timestamp = gettimestamp(scanhistory)
        context = {'serverip': serverip,
                   'list_timestamp': list_timestamp,
                   'error': error}
        return render(request, 'scanner/networkscanner.html', context)

    downloadServerFile(sshClient, filename, 'scannerlogs/{}'.format(name))

    sshClient.close()

    return redirect(index)

#To copy the file the user input into scannerlogs folder.
def inputfile(request):
    if request.method == "POST":
        path = request.POST['filepath']
        newname = request.POST['newname']
        finalpath = r'{}'.format(path)

        if path == '' or os.path.isfile(finalpath)==False:
            empty = 'empty'
            serverip = SSHCred.objects.filter(servertype='scanning')
            scanhistory = sorted_ls(os.getcwd() + '/scannerlogs')
            list_timestamp = gettimestamp(scanhistory)
            context = {'serverip': serverip,
                       'list_timestamp': list_timestamp,
                       'empty':empty}
            return render(request, 'scanner/networkscanner.html', context)



        shutil.copy(finalpath,'scannerlogs/'+newname)
        serverip = SSHCred.objects.filter(servertype='scanning')
        scanhistory = sorted_ls(os.getcwd() + '/scannerlogs')
        list_timestamp = gettimestamp(scanhistory)
        context = {'serverip': serverip,
                   'list_timestamp': list_timestamp}
        return render(request, 'scanner/networkscanner.html', context)

#Delete the selected xml file from the scannerlogs folder.
def removelog(request, filename):
    os.remove('scannerlogs/'+filename)
    return redirect(index)

#Split the filename to get the timestamp of when the scan was conducted.
def gettimestamp(scanhistory):
    datetime = []
    timestamp = []
    for i in scanhistory:
        date = []
        time = []
        if "nmap_masscan" in i:
            a, b, c, d = i.split("_")
            date.append(c)
            d = d.strip(".xml")
            time.append(d)
        elif "nmaplog" in i:
            a, b, c = i.split("_")
            date.append(b)
            c = c.strip(".xml")
            time.append(c)
        elif "masscanlog" in i:
            a, b, c = i.split("_")
            date.append(b)
            c = c.strip(".xml")
            time.append(c)
        else:
            date.append("-")
            time.append("-")
        datetime.append(date)
        timestamp.append(time)

    list_timestamp = zip(scanhistory, datetime, timestamp)

    return list_timestamp