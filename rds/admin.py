from django.contrib import admin

from rds.models import Rds
from rds.models import RdsList

admin.site.register(Rds)
admin.site.register(RdsList)
