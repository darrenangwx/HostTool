from django.db import models
from django.dispatch import receiver
from django.db.models.signals import pre_delete
from django.conf import settings
from main.models import SSHCred
from main.lib import *

# Create your models here.
class Honeypot(models.Model):
    name = models.CharField(max_length=100)
    log_path = models.CharField(max_length=1000, null=True, blank=True)
    imagename = models.CharField(max_length=1000, null=True, blank=True)
    port_mappings = models.CharField(max_length=1000, null=True, blank=True)
    giturl = models.CharField(max_length=1000, null=True, blank=True)
    folder = models.CharField(max_length=1000, null=True, blank=True)
    generatescript = models.CharField(max_length=1000, null=True, blank=True)
    log_pattern = models.CharField(max_length=100, null=True, blank=True)
    binaries_path = models.CharField(max_length=1000, null=True, blank=True)
    script = models.CharField(max_length=1000, null=True, blank=True)
    default = models.BooleanField(default=False)

    def __str__(self):
        return self.name

class Deployment(models.Model):
    honeypot = models.ForeignKey(Honeypot,on_delete=models.CASCADE)
    sshCred = models.ForeignKey(SSHCred,on_delete=models.CASCADE)
    docker_id = models.CharField(max_length=1000)
    build = models.BooleanField(default=False)
    mountvolume = models.CharField(max_length=1000, null=True, blank=True)
    binariesvolume = models.CharField(max_length=1000, null=True, blank=True)

    def __str__(self):
        return '{} ({})'.format(self.honeypot.name, self.sshCred)

    @receiver(pre_delete)
    def cleanup(sender, instance, using, **kwargs):
        from honeypot.lib import getMonitoredFiles, removeMonitorFile, getDeploymentSSH

        # Cleanup when deleting deployment
        if sender == Deployment:
            deployment_id = instance.id

            parameters = {
                'deployment_id': deployment_id,
                'docker_id': instance.docker_id,
                'docker_logs_volume': instance.mountvolume,
                'docker_binaries_volume': instance.binariesvolume,
                'log_folder': settings.LOG_FOLDER
            }

            buildlog = '{log_folder}/deployment_{deployment_id}_build.log'.format(**parameters)
            deleteFile(buildlog)

            monitoredFiles = getMonitoredFiles(deployment_id)
            for i in monitoredFiles:
                removeMonitorFile(deployment_id,i)

            sshClient = getDeploymentSSH(deployment_id)
            if sshClient:
                try:
                    if parameters['docker_id']:
                        # Stop and remove docker container
                        command = 'docker stop {docker_id} && docker rm {docker_id}'.format(**parameters)
                        executeSSH(sshClient, command)

                    if parameters['docker_logs_volume']:
                        # Remove logs volume
                        command = 'docker volume rm {docker_logs_volume}'.format(**parameters)
                        executeSSH(sshClient, command)

                    if parameters['docker_binaries_volume']:
                        # Remove binaries volume
                        command = 'docker volume rm {docker_binaries_volume}'.format(**parameters)
                        executeSSH(sshClient, command)
                except:
                    pass

                sshClient.close()