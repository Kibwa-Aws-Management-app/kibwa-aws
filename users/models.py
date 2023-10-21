from __future__ import unicode_literals

from django.db import models
from django.utils import timezone


class User(models.Model):
    root_id = models.CharField(max_length=200, primary_key=True, unique=True)
    password = models.CharField(max_length=200)

    # class Meta:
    #     db_table = "user"
    def __str__(self):
        return f"User-{str(self.root_id)}"
