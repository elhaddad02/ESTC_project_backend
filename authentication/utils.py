# utils.py

from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import threading
import logging
from django.conf import settings
import os
from django.utils.html import strip_tags
from django.core.mail import send_mail


logger = logging.getLogger(__name__)

class EmailThread(threading.Thread):
    def __init__(self, email):
        super().__init__()
        self.email = email

    def run(self):
        try:
            self.email.send()
            logger.info(f"Email sent to {self.email.to}")
        except Exception as e:
            logger.error(f"Failed to send email to {self.email.to}: {e}", exc_info=True)

class Util:
    @staticmethod
    def send_email_verification(user, verification_url):
        subject = "Welcome to Univers France Succes"
        html_message = render_to_string("verification_email.html", {
            'verification_url': verification_url,
            'user': user  # Si besoin d'afficher le nom/prénom dans l'email
        })
        plain_message = strip_tags(html_message)  # Version texte de l'email
        
        email = EmailMessage(
            subject=subject,
            body=html_message,
            from_email=settings.EMAIL_HOST_USER,
            to=[user.email]
        )
        email.content_subtype = "html"  # Indiquer que l'email est en HTML
        
        # Utilisation de `EmailThread` pour ne pas bloquer l'exécution
        EmailThread(email).start()
    
    @staticmethod
    def send_password_reset_email(request, user):
        """
        Send a password reset link to the user.
        """
        domaine="https://app.universfrancesucces.com"

        token = PasswordResetTokenGenerator().make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        current_site = get_current_site(request).domain
        #relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uid, 'token': token})
        relative_link = f'/password-reset-confirm/{uid}/{token}/'

        #abs_url = f'{request.scheme}://{current_site}{relative_link}'
        abs_url = f'{domaine}{relative_link}'
        print(relative_link)
        email_subject = 'modifier le mot passe '
        email_body = f'Bonjour ,\n\n Visiter ce lien pour modifier le mot passe de votre compte :\n{abs_url}'
        Util.send_email(email_subject, email_body, user.email)
        return uid,token

 #envoyer email servide asssurance 
 
    @staticmethod
    def send_assurance_email(request, user):
        """
        Send a password reset link to the user.
        """
        domaine="https://app.universfrancesucces.com"

        token = PasswordResetTokenGenerator().make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        current_site = get_current_site(request).domain
        #relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uid, 'token': token})
        relative_link = f'/password-reset-confirm/{uid}/{token}/'

        #abs_url = f'{request.scheme}://{current_site}{relative_link}'
        abs_url = f'{domaine}{relative_link}'
        print(relative_link)
        email_subject = 'Service assurance '
        email_body = f'Hi {user.username},\n\n vous avez effectuer une service  :\n'
        Util.send_email(email_subject, email_body, user.email)
    @staticmethod
    def send_email(email_subject, email_body, to_email, from_email=None):
        """
        Utility function to send an email.
        """
        if from_email is None:
            from_email = settings.DEFAULT_FROM_EMAIL  # Use Django settings for default from_email
        email = EmailMessage(
            subject=email_subject,
            body=email_body,
            from_email=from_email,
            to=[to_email]
        )
        EmailThread(email).start()
        
    # @staticmethod
    # def send_templated_email(template_name, recipients, context):
    #     try:
    #         template = EmailTemplate.objects.get(name=template_name)
    #     except EmailTemplate.DoesNotExist:
    #         raise ValueError("Template does not exist")

    #     subject = template.subject
    #     body = render_to_string(template.content, context)
        
    #     email = EmailMessage(
    #         subject=subject,
    #         body=body,
    #         from_email=settings.DEFAULT_FROM_EMAIL,
    #         to=recipients
    #     )
    #     EmailThread(email).start()
