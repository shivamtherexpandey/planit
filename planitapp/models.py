from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# Create your models here.
class SocialToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    access_token = models.TextField()
    refresh_token = models.TextField()
    profile_pic_link = models.CharField(max_length=255)
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(auto_now=True)
