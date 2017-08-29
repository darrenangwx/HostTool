from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='scanner'),
    url(r'^startscan$', views.startscan, name='startscan'),
    url(r'^details/(.+)$', views.details, name='details'),
    url(r'^nmap_masscan/$', views.nmap_masscan, name='nmap_masscan'),
    url(r'^inputfile$', views.inputfile, name='inputfile'),
    url(r'^removelog/(.+)$', views.removelog, name='removelog')
]