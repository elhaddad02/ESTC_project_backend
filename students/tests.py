from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, Student, Parents, Program, File, IrrevocablePaymentCertificate, HousingSearch
from datetime import date
import logging
from Chat.models import Notification

logger = logging.getLogger(__name__)

@receiver(post_save, sender=User)
def create_profile_and_related_models(sender, instance, created, **kwargs):
    if created and instance.role == 'student':
        logger.info(f'Creating profile for student: {instance}')
        student, created = Student.objects.get_or_create(user=instance)
        if created:
            Parents.objects.create(student=student)
            Program.objects.create(student=student)
            logger.info(f'Profile and related models created for student: {instance}')
        else:
            logger.info(f'Profile already exists for student: {instance}')

@receiver(post_save, sender=Student)
def create_related_models_for_profile(sender, instance, created, **kwargs):
    if created:
        logger.info(f'Creating related models for student: {instance}')
        files = File.objects.create()
        IrrevocablePaymentCertificate.objects.create(user=instance.user, files=files)
        HousingSearch.objects.create(
            user=instance.user,
            move_in_date=date.today(),  # Provide a default value for move_in_date
            accommodation_type='default_type',  # Provide a default value
            preferred_location='default_location',  # Provide a default value
            stay_duration=0,  # Provide a default value
            budget=0.00,  # Provide a default value
        )
        logger.info(f'Related models created for student: {instance}')
    else:
        logger.info(f'Related models already exist for student: {instance}')

@receiver(post_save, sender=User)
def profile_update_notification(sender, instance, created, **kwargs):
    if not created and instance.role == 'student':
        Notification.objects.create(
            user=instance,
            message="Your profile has been updated"
        )
