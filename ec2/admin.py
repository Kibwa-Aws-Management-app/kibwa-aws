from django.contrib import admin

from ec2.models import Ec2
from ec2.models import Ec2List

admin.site.register(Ec2)
admin.site.register(Ec2List)
