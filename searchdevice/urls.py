from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='searchdevice_shodan'),
    url(r'^censys/$', views.censys, name='censys'),
    url(r'^details/shodan$', views.shodan_details, name='shodan_details'),
    url(r'^details/censys$', views.censys_details, name='censys_details'),
    url(r'^details/censys_api$', views.censys_api,name='censys_api'),
    url(r'^shodan_masscan/$', views.shodan_masscan, name='shodan_masscan'),
    url(r'^shodan_masscan_api/$', views.shodan_masscan_api, name='shodan_masscan_api'),
    url(r'^vulnerability_filter/$', views.vulnerability_filter, name='vulnerability_filter'),
    url(r'^vulnerability_filter/delete/(?P<id>\d+)/$', views.vulnerability_filter_delete, name='vulnerability_filter_delete'),

]