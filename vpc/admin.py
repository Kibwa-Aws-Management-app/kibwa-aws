from django.contrib import admin

from vpc.models import Vpc
from vpc.models import VpcList

admin.site.register(Vpc)
admin.site.register(VpcList)
