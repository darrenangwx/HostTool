from django.shortcuts import render, HttpResponse
from urllib.error import *
from urllib.request import urlopen
import json
from main.models import *
import requests
from django.http import JsonResponse
from distutils.version import LooseVersion
from .models import *


def index(request):
    # Get API Key from database and list out in the template
    api_keys = ApiKey.objects.filter(type__type_name='Shodan')
    # If api key and query exist in POST Request. Start to render credits!
    if 'api_key' and 'query' in request.POST:
        api_key = request.POST.get("api_key")
        query = request.POST.get("query")
        # Status Check RESTFul Api Shodan
        status_url = "https://api.shodan.io/api-info?key=" + api_key + ""
        # Get data from Shodan to retrieve Credits
        try:
            status_response = urlopen(status_url)
            status_data = status_response.read()
            status_values = json.loads(status_data)
            # If API has an error..
        except HTTPError:
            return render(request, 'searchdevice/shodan.html', {
                'error_message': 'Invalid Key',
                'api_keys': api_keys,
                'query_title': query,

            })
        return render(request, 'searchdevice/shodan.html', {
            'query_title': query,
            'api_key': api_key,
            'status_values': status_values,
            'api_keys': api_keys,
            'success_message': status_values,
        })
    else:
        return render(request, 'searchdevice/shodan.html', {
            'api_keys': api_keys
        })


def shodan_details(request):
    ip = request.GET.get('ip')
    api_key = request.GET.get('api_key')

    return render(request, 'searchdevice/details.html', {
        'ip': ip,
        'api_key': api_key,
    })


def censys_api(request):
    ip = request.GET.get('ip')
    api_key = request.GET.get('api_key')
    api_secret = request.GET.get('api_secret')

    if 'api_key' and 'api_secret' and 'ip' in request.GET:
        API_URL = "https://www.censys.io/api/v1/view/ipv4/"
        res = requests.get(API_URL + ip, auth=(api_key, api_secret))
        return JsonResponse(res.json(), safe=False)

    if 'UID' and 'secret' and 'query' in request.GET:
        query_title = request.GET.get('query')
        API_URL = "https://www.censys.io/api/v1"
        UID = request.GET.get("UID")
        secret = request.GET.get("secret")

        # Post queries and data to censys!
        data = {
            "query": ("%s" % query_title),
        }

        res = requests.post(API_URL + "/search/ipv4", auth=(UID, secret), data=json.dumps(data))

        # If the api don't work..
        if res.status_code != 200:
            return HttpResponse('API Don\' work')

        else:
            return HttpResponse(json.dumps(res.json()), content_type='application/json')

    return HttpResponse('No API Key/Secret')


def censys_details(request):
    ip = request.GET.get('ip')
    api_key = request.GET.get('api_key')
    api_secret = request.GET.get('api_secret')

    return render(request, 'searchdevice/censysdetails.html', {
        'ip': ip,
        'api_key': api_key,
        'api_secret': api_secret,
    })


def censys(request):
    api_keys = ApiKey.objects.filter(type__type_name='Censys')

    if 'UID' and 'secret' and 'query' in request.POST:
        api_key = request.POST.get("UID")
        api_secret = request.POST.get("secret")
        query = request.POST.get("query")

        # Check validity of API
        res = requests.get("https://www.censys.io/api/v1/data", auth=(api_key, api_secret))

        # If don't work
        if res.status_code != 200:
            return render(request, 'searchdevice/censys.html', {
                'error_message': 'API Validation Failed. Error code:200',
                'api_key': api_key,
                'api_keys': api_keys,
                'api_secret': api_secret,
                'query': query,
            })

        return render(request, 'searchdevice/censys.html', {
            'api_key': api_key,
            'api_keys': api_keys,
            'api_secret': api_secret,
            'query': query,
        })
    else:
        return render(request, 'searchdevice/censys.html', {
            'api_keys': api_keys,
        })


def shodan_masscan_api(request):
    ip_list = request.session.get('listofip')
    api_key = request.GET.get('api_key')
    # Vulnerable dictionary.. Below is an example.
    # vulnerable = {'samba': ('0.0.0', '3.6.25'), 'mysql': ('0.0.0', '5.5.5')}

    vulnerable = {}

    # Retrieve vulnerable list in the database, add it into dictionary
    all_vulnerabilities = Vulnerability.objects.all()
    for vulnerability in all_vulnerabilities:
        vulnerable[vulnerability.service] = (vulnerability.lowest_version, vulnerability.highest_version)

    # Define a list of new ip, so that we can export all the details as json in th end.
    new_ip_list = []

    # If listofip exists in session..
    if ip_list:
        # It will loop through the ip_list..
        for ip in ip_list:
            # And get the data from shodan..
            res_data = requests.get(
                "https://api.shodan.io/shodan/host/" + ip + "?key=" + api_key).json()
            # If data[] exist in the returned result..
            if 'data' in res_data:
                # For every services in data[] segment..
                for service in res_data['data']:
                    port = service['port']
                    ip_str = service['ip_str']
                    # If version and product DOES exist in the data[] Check through the vulnerability dict.
                    if 'product' and 'version' in service:
                        product = service['product'].lower()
                        version = service['version'].lower()
                        # Iterating through the vulnerability dictionary..
                        for key, value in vulnerable.items():
                            # If exist in vulnerability dictionary..
                            if key.lower() in product and LooseVersion(value[0]) <= version <= LooseVersion(value[1]):
                                print(
                                    "IP:" + service['ip_str'] + " port:" + str(
                                        service['port']) + " Vulnerable product: " +
                                    service['product'] + " Version:" + service['version'])
                                new_ip_list.append(
                                    dict({"ip": ip_str, "port": port, "product": product,
                                          "version": version,
                                          "vulnerable": product + ' ' + version + ' is vulnerable'}))
                        # Append the list if it's not found under vulnerable{}
                        if not any(d['port'] == port for d in new_ip_list):
                            print(
                                "IP:" + service['ip_str'] + " port:" + str(
                                    service['port']) + " Not Vulnerable product: " +
                                service['product'] + "Version:" + service['version'])

                            new_ip_list.append(dict({"ip": ip_str, "port": port, "product": product,
                                                     "version": version, "vulnerable": 0}))

                    # If data['product'] or data['version'] doesn't exist just output as vulnerable:0
                    else:
                        # https://stackoverflow.com/questions/3897499/check-if-value-already-exists-within-list-of-dictionaries
                        if not any(d['port'] == port for d in new_ip_list):
                            new_ip_list.append(dict({"ip": ip_str, "port": port, "vulnerable": 0}))
                            print("IP:" + service['ip_str'] + " Port:" + str(service['port']))

        # Retuen as JSON Format
        return HttpResponse(json.dumps(new_ip_list), content_type='application/json')
    else:
        # Return as an error
        return HttpResponse('No list of ip captured.')


def shodan_masscan(request):
    ip_list = request.session.get('listofip')
    if request.method == "POST":
        api_key = request.POST['apikey']
        request.session['api_key'] = api_key
    else:
        return render(request, 'searchdevice/shodan_masscan.html', {
            'error_message': 'No list of IP from masscan'
        })
    if ip_list:
        return render(request, 'searchdevice/shodan_masscan.html', {
            'ip_list': ip_list,
            'api_key': api_key
        })
    else:
        return render(request, 'searchdevice/shodan_masscan.html', {
            'error_message': 'No list of IP from masscan'
        })


def vulnerability_filter(request):
    if 'service' and 'lowest_version' and 'highest_version' in request.POST:
        service = request.POST.get('service')
        lowest_version = request.POST.get('lowest_version')
        highest_version = request.POST.get('highest_version')

        vulnerability_obj = Vulnerability(service=service, lowest_version=lowest_version,
                                          highest_version=highest_version)
        vulnerability_obj.save()

        return render(request, 'searchdevice/vulnerability_filter.html', {
            'success_message': 'Successfully added the filter.',
            'vulnerability_filer_objects': Vulnerability.objects.all()
        })
    else:
        return render(request, 'searchdevice/vulnerability_filter.html', {
            'vulnerability_filer_objects': Vulnerability.objects.all()
        })


def vulnerability_filter_delete(request, id):
    if id is not None:
        delete_object = Vulnerability.objects.filter(id=id)

        if delete_object.exists():
            delete_object.delete()
            return render(request, 'searchdevice/vulnerability_filter.html', {
                'success_message': 'Deleted filter id ' + id,
                'vulnerability_filer_objects': Vulnerability.objects.all()
            })
        else:
            return render(request, 'searchdevice/vulnerability_filter.html', {
                'error_message': 'Id ' + id + ' not found',
                'vulnerability_filer_objects': Vulnerability.objects.all()
            })

    else:
        return render(request, 'searchdevice/vulnerability_filter.html', {
            'error_message': 'Id ' + id + ' not found',
            'vulnerability_filer_objects': Vulnerability.objects.all()
        })
