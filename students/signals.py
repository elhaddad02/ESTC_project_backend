from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from .models import Student, User
import logging

logger = logging.getLogger(__name__)

