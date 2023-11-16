from django.contrib import admin

from s3.models import S3
from s3.models import S3List

admin.site.register(S3)
admin.site.register(S3List)
