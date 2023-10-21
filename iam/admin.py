from django.contrib import admin

from iam.models import Iam
from iam.models import IamList

admin.site.register(Iam)
admin.site.register(IamList)
