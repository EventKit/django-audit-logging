from __future__ import unicode_literals

from django.db import models

class TestModel(models.Model):
    field1 = models.CharField(max_length=120)
