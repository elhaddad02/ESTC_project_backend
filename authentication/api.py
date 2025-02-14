import logging
import os

import jwt
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.http import HttpResponsePermanentRedirect
from django.shortcuts import redirect
from django.utils import translation
from django.utils.encoding import smart_str
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import gettext as _
from rest_framework import generics, permissions, status
from rest_framework.response import Response
import environ

from .models import User
from .renderers import UserRenderer
from .serializers import *
from .utils import Util


import environ

v = environ.Env()
environ.Env.read_env()

logger = logging.getLogger(__name__)

class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        response_data = {
            "user": serializer.data,
            "message": _("Utilisateur créé avec succès. Veuillez vérifier votre e-mail pour vérification.")
        }
        return Response(response_data, status=status.HTTP_201_CREATED)

class VerifyEmail(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer
    renderer_classes = [UserRenderer]
    def get2(self, request):
        # Récupérer le Bearer Token dans l'en-tête Authorization
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            raise AuthenticationFailed("Authorization header missing")
        
        # Le token Bearer est généralement sous la forme 'Bearer <token>'
        parts = auth_header.split()
        
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise AuthenticationFailed("Invalid Authorization header format")
        
        token = parts[1]
        
        # Afficher le token (par exemple, dans la réponse)
        #return Response({"token": token})

    def get(self, request):
        token = request.GET.get('token')  # Correction ici
        print("affiche",token)
        if not token:
            return Response({'erreur': _('Jeton non fourni')}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
        except jwt.ExpiredSignatureError:
            logger.error(_("Lien d'activation expiré."))
            return Response({'erreur': _("Lien d'activation expiré")}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError:
            logger.error(_('Jeton invalide.'))
            return Response({'erreur': _('Jeton invalide')}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            logger.error(_('User not found.'))
            return Response({'erreur': _('Utilisateur non trouvé')}, status=status.HTTP_404_NOT_FOUND)

        if user.is_verified:
            # frontend_url = "http://localhost:3000"
            frontend_url = "https://app.universfrancesucces.com"
            redirection_url = f"{frontend_url}/etudiant/login"
            return redirect(redirection_url)  # Change en fonction de ton URL de connexion

        user.is_verified = True
        user.save()
        logger.info(_('Utilisateur activé avec succès..'))
        
        # frontend_url = "http://localhost:3000"
        frontend_url = "https://app.universfrancesucces.com"
        redirection_url = f"{frontend_url}/etudiant/login"


        return redirect(redirection_url)  # Change en fonction de ton URL de connexion

class ResendVerification(generics.GenericAPIView):

    serializer_class = ResendVerificationSerializer
    renderer_classes = [UserRenderer]


    def post(self, request):

        serializer = self.get_serializer(data=request.data)
        
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            
            if user.is_verified:
                return Response({'erreur': _("L'utilisateur est déjà vérifié.")}, status=status.HTTP_400_BAD_REQUEST)

            Util.send_email_verification(request, user=user)

            response_data = {
                "message": _("E-mail de vérification envoyé.")
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'erreur': _('Utilisateur non trouvé.')}, status=status.HTTP_404_NOT_FOUND)

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    renderer_classes = [UserRenderer]

    def post(self, request):
        # Pass request into serializer context
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Vous vous êtes déconnecté avec succès."}, status=status.HTTP_204_NO_CONTENT)

class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    renderer_classes = [UserRenderer]
    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        user = User.objects.get(email=serializer.validated_data['email'])
        uid,token=Util.send_password_reset_email(request, user)
        print("from last one :",uid,token)
        return Response({"uid": uid, "token": token}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    permission_classes = [permissions.AllowAny]
    renderer_classes = [UserRenderer]

    def patch(self, request, uidb64, token, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        print(serializer.validated_data['password'])
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': _("Le lien de réinitialisation n'est pas valide")}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(serializer.validated_data['password'])
            user.save()
            return Response({"message": _("Réinitialisation du mot de passe réussie.")}, status=status.HTTP_200_OK)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'erreur': _("Le lien de réinitialisation n'est pas valide")}, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get_object(self, queryset=None):
        return self.request.user

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            serializer.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Mot de passe mis à jour avec succès',
                'data': []
            }
            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)