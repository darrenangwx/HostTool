from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='servermanager'),
    url(r'^ssh/$', views.ssh, name='ssh'),
    url(r'^ssh/json/(?:(?P<type>.*)/)?$', views.sshjson, name='sshjson'),
    url(r'^ssh/table/?$', views.sshtable, name='sshtable'),
    url(r'^add/$', views.addssh, name='addssh'),
    url(r'^ssh/edit/$', views.editssh, name='editssh'),
    url(r'^delete/(?:(?P<ssh_id>[0-9]+)/)?$', views.delete, name='delete'),
    url(r'^add/loading$', views.loadingtext, name='loading'),
]