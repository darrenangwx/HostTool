from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^manage/apikeys/$', views.apikeymanager, name='apikeymanager'),
    url(r'^manage/apikeys/add/$', views.addapikey, name='addapikey'),
    url(r'^manage/apikeys/delete/(?P<apikey_id>[0-9]+)/$', views.deleteapikey, name='deleteapikey'),
    url(r'^manage/apikeys/edit/(?:(?P<apikey_id>[0-9]+)/)?$', views.editapikey, name='editapikey'),
]