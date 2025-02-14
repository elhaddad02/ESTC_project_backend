import logging
from rest_framework.views import APIView
from rest_framework.exceptions import NotFound, PermissionDenied
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework import generics, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import (NotFound, PermissionDenied,
                                       ValidationError)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from authentication.permissions import IsStudentAuthenticated,IsParentAuthenticated


from .models import *
from .serializers import *

from authentication.permissions import IsStudentAuthenticated

from .models import *
from .serializers import *

logger = logging.getLogger(__name__)

class StudentRegistrationView(generics.CreateAPIView):
    serializer_class = StudentRegistrationSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        logger.info('Received registration request: %s', request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        student = serializer.save()
        response_data = {
            "student": serializer.data,
            "message": "Student created successfully."
        }
        logger.info('Student created successfully: %s', student)
        return Response(response_data, status=status.HTTP_201_CREATED)
class StudentProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = StudentProfileSerializer
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    def get_object(self):
        try:
            return self.request.user.student
        except Student.DoesNotExist:
            raise NotFound("Student does not exist")

    def get(self, request, *args, **kwargs):
        student = self.get_object()
        self._ensure_related_entries(student)
        serializer = self.get_serializer(student)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        student = self.get_object()
        self._ensure_related_entries(student)
        serializer = self.get_serializer(student, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        student = self.get_object()
        self._ensure_related_entries(student)
        serializer = self.get_serializer(student, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def _ensure_related_entries(self, student):
        Guardian.objects.get_or_create(student=student)
        Program.objects.get_or_create(student=student)

# Vue permettant de gérer les modèles de templates d'e-mails
# class EmailTemplateViewSet(viewsets.ModelViewSet):
#     # Récupère tous les modèles EmailTemplate dans la base de données
#     queryset = EmailTemplate.objects.all()
#     # Utilise le sérialiseur EmailTemplateSerializer pour valider et transformer les données
#     serializer_class = EmailTemplateSerializer
#     permission_classes = [IsAuthenticated]


# Vue générique pour envoyer des e-mails
class SendEmailView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SendEmailSerializer

    # Méthode POST pour envoyer des e-mails
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Récupère les données validées : sujet, contenu et IDs des destinataires
        subject = serializer.validated_data["subject"]
        body = serializer.validated_data["body"]
        recipient_ids = serializer.validated_data["recipient_ids"]

        # Filtre les utilisateurs à partir des IDs fournis
        recipients = User.objects.filter(id__in=recipient_ids)
        for recipient in recipients:
            # Utilise une méthode utilitaire pour envoyer un e-mail à chaque destinataire
            Util.send_email(subject, body, recipient.email)

        return Response({"message": "Emails sent successfully"}, status=status.HTTP_200_OK)


'''class CertificateView(generics.RetrieveUpdateAPIView):
    serializer_class = IrrevocablePaymentCertificateSerializer
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    def get_object(self):
        user = self.request.user
        try:
            return user.payment_certificates
        except IrrevocablePaymentCertificate.DoesNotExist:
            raise NotFound("Certificate does not exist")

    def get(self, request, *args, **kwargs):
        certificate = self.get_object()
        serializer = self.get_serializer(certificate)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        certificate = self.get_object()
        serializer = self.get_serializer(certificate, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        # Send email notification
        send_notification(
            request.user,
            "Votre certificat de paiement irrevocable a été mis à jour.",
            "Certificat de paiement irrevocable mis à jour"
        )

        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        user = request.user

        # Check if there's an existing certificate; if not, create a new one
        certificate = IrrevocablePaymentCertificate.objects.filter(user=user).first()

        if certificate:
            # If a certificate exists, update it
            serializer = self.get_serializer(certificate, data=request.data)
            action_message = "mise à jour"
        else:
            # Otherwise, create a new certificate
            serializer = self.get_serializer(data=request.data)
            action_message = "créé"

        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Send confirmation email
        send_notification(
            user,
            f" {action_message} avec succès.",
            f"{action_message}"
        )

        status_code = status.HTTP_201_CREATED if not certificate else status.HTTP_200_OK
        return Response(serializer.data, status=status_code)'''
        
class CertificateView(generics.RetrieveUpdateAPIView):
    serializer_class = IrrevocablePaymentCertificateSerializer
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    def get_object(self):
        user = self.request.user
        try:
            return user.payment_certificates
        except IrrevocablePaymentCertificate.DoesNotExist:
            raise NotFound("Certificate does not exist")
        
    def send_confirmation_email(self, user_id, service_name):
        """
        Méthode pour envoyer une notification par e-mail lors de l'abonnement.
        """
        from django.core.mail import send_mail
        from django.contrib.auth import get_user_model
        User = get_user_model()

        try:
            user = User.objects.get(id=user_id)
            subject = "Confirmation de votre abonnement"
            body = f"Vous avez été abonné avec succès au service {service_name}."

            send_mail(
                subject=subject,
                message=body,
                from_email="no-reply@votreapp.com",
                recipient_list=[user.email],
            )
        except User.DoesNotExist:
            raise NotFound("Utilisateur introuvable pour envoyer l'e-mail.")

    def get(self, request, *args, **kwargs):
        certificate = self.get_object()
        serializer = self.get_serializer(certificate)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        certificate = self.get_object()
        serializer = self.get_serializer(certificate, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        # Send email notification
        self.send_confirmation_email(
            request.user.id,
            "Votre certificat de paiement irrevocable a été mis à jour."
        )

        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        user = request.user

        certificate = IrrevocablePaymentCertificate.objects.filter(user=user).first()

        if certificate:
            serializer = self.get_serializer(certificate, data=request.data)
            action_message = "mise à jour"
        else:
            serializer = self.get_serializer(data=request.data)
            action_message = "créé"

        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Send confirmation email
        self.send_confirmation_email(
            user.id,
            f"Votre certificat de paiement irrevocable a été {action_message} avec succès."
        )

        status_code = status.HTTP_201_CREATED if not certificate else status.HTTP_200_OK

        return Response(serializer.data, status=status_code)



class DeleteCertificateFile(APIView):
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    @swagger_auto_schema(
        operation_description="Deletes a specific file from the IrrevocablePaymentCertificate object associated with the authenticated user",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'file_field': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    enum=['preliminary_acceptance', 'payment_proof', 'passport_copy', 'additional_pdf'],
                    description="The file field to be deleted."
                )
            },
            required=['file_field'],
        ),
        responses={
            200: openapi.Response('File deleted successfully'),
            404: 'Certificate not found or file does not exist',
            400: 'Invalid request, file field not specified or incorrect',
        }
    )
    def delete(self, request, *args, **kwargs):
        user = request.user

        # Retrieve the certificate associated with the authenticated user
        certificate = IrrevocablePaymentCertificate.objects.filter(user=user).first()

        if not certificate:
            raise NotFound("Irrevocable Payment Certificate does not exist or does not belong to you.")

        file_field = request.data.get('file_field')
        if not file_field:
            raise PermissionDenied("You must specify a file field to delete.")

        valid_file_fields = ['preliminary_acceptance', 'payment_proof', 'passport_copy', 'additional_pdf']
        if file_field not in valid_file_fields:
            raise PermissionDenied(f"{file_field} is not a valid file field.")

        # Check if the specified file exists on the certificate
        file_obj = getattr(certificate.files, file_field, None)
        if file_obj and file_obj.name:
            # Delete the file
            file_obj.delete()

            # Set the file field to None and save the certificate
            setattr(certificate.files, file_field, None)
            certificate.files.save()

            return Response({"detail": f"File {file_field} deleted successfully."}, status=status.HTTP_200_OK)
        else:
            raise NotFound(f"{file_field} does not exist or is already null.")




class HousingSearchView(generics.RetrieveUpdateAPIView):
    serializer_class = HousingSearchSerializer
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    def get_object(self):
        user = self.request.user
        housing_search = user.housing_searches.first()
        if not housing_search:
            raise NotFound("Housing search does not exist")
        return housing_search

    def get(self, request, *args, **kwargs):
        housing_search = self.get_object()
        serializer = self.get_serializer(housing_search)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        housing_search = self.get_object()
        serializer = self.get_serializer(housing_search, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        user = self.request.user
        # Vérifie s'il existe déjà une demande de logement, sinon en créer une nouvelle
        housing_search = user.housing_searches.first()
        if housing_search:
            # Si un enregistrement existe, on le met à jour
            serializer = self.get_serializer(housing_search, data=request.data)
        else:
            # Sinon, on crée un nouvel enregistrement
            serializer = self.get_serializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        serializer.save()
    # Si une nouvelle demande est créée, on envoie l'e-mail de confirmation
        if not housing_search:
            self.send_confirmation_email(user.id, "Recherche de logement")
            
        # Envoi de l'e-mail de confirmation
        # self.send_confirmation_email(user.id, "Recherche de logement")

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def send_confirmation_email(self, user_id, service_name):
        """
        Méthode pour envoyer une notification par e-mail lors de l'abonnement.
        """
        from django.core.mail import send_mail
        from django.contrib.auth import get_user_model

        User = get_user_model()

        try:
            user = User.objects.get(id=user_id)
            subject = "Confirmation de votre abonnement"
            body = f"Vous avez été abonné avec succès au service {service_name}."

            send_mail(
                subject=subject,
                message=body,
                from_email="no-reply@votreapp.com",
                recipient_list=[user.email],
            )
        except User.DoesNotExist:
            raise NotFound("Utilisateur introuvable pour envoyer l'e-mail.")    

    # Méthode pour supprimer des fichiers spécifiques
    def patch(self, request, *args, **kwargs):
        housing_search = self.get_object()  # Récupérer l'objet lié à l'utilisateur
        files_to_delete = request.data.get("files_to_delete", [])

        if not isinstance(files_to_delete, list):
            return Response({"error": "files_to_delete must be a list"}, status=status.HTTP_400_BAD_REQUEST)
            
        # Supprimer les fichiers spécifiés
        for file_field in files_to_delete:
            if hasattr(housing_search.files, file_field):
                file = getattr(housing_search.files, file_field)
                if file:
                    # Supprimer physiquement le fichier du système de fichiers
                    file.delete(save=False)
                    # Supprimer la référence dans l'objet Files
                    setattr(housing_search.files, file_field, None)
    
        housing_search.files.save()  # Sauvegarder les modifications

        # Retourner une réponse de succès
        return Response({"message": "Fichiers supprimés avec succès"}, status=status.HTTP_200_OK)



class InsuranceView(generics.RetrieveUpdateAPIView):
    serializer_class = InsuranceSerializer
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    # Méthode DELETE pour supprimer l'assurance de l'utilisateur
    def delete(self, request, *args, **kwargs):
        user = self.request.user
        
        if user.is_anonymous:
            raise PermissionDenied("Vous devez être connecté pour supprimer l'assurance.")
        
        try:
            insurance = self.get_object()
            insurance.delete()  # Supprime l'objet assurance
            print("assurance deleted")
            return Response({"message": "L'assurance a été supprimée avec succès."}, status=status.HTTP_200_OK)
        except NotFound:
            raise NotFound("Aucune assurance trouvée pour cet utilisateur.")
    def get_object(self):
        user = self.request.user
        if user.is_anonymous:
            raise PermissionDenied("You must be logged in to access this resource.")

        try:
            return user.insurance
        except Insurance.DoesNotExist:
            raise NotFound("Insurance policy does not exist")

    def get(self, request, *args, **kwargs):
        if request.user.is_anonymous:
            raise PermissionDenied("You must be logged in to view this insurance policy.")
        
        insurance = self.get_object()
        serializer = self.get_serializer(insurance)
        
        return Response(serializer.data)

    def send_confirmation_email(self, user_id):
        """
        Méthode pour envoyer une notification par e-mail lors de l'abonnement.
        """
        from django.core.mail import send_mail
        from django.contrib.auth import get_user_model
        User = get_user_model()

        try:
            user = User.objects.get(id=user_id)
            subject = "Assurance enregistrée avec succés"
            body = f"Votre assurance a été enregistrée avec succés  ."

            send_mail(
                subject=subject,
                message=body,
                from_email="no-reply@votreapp.com",
                recipient_list=[user.email],
            )
        except User.DoesNotExist:
            raise NotFound("Utilisateur introuvable pour envoyer l'e-mail.")    
        
    def update(self, request, *args, **kwargs):
        user = self.request.user
        
        if user.is_anonymous:
            raise PermissionDenied("Vous devez être connecté pour mettre à jour cette assurance.")
        
        # Récupérer l'ancienne assurance de l'utilisateur
        try:
            insurance = self.get_object()  # Utilisation de get_object pour récupérer l'assurance existante
        except NotFound:
            raise NotFound("Aucune assurance trouvée pour cet utilisateur.")

        # Supprimer l'ancienne assurance
        #insurance.delete()

        # Créer la nouvelle assurance
        serializer = self.get_serializer(insurance,data=request.data)
        serializer.is_valid(raise_exception=True)
        new_insurance = serializer.save()
        if(self.request.user):
        
          print("user for update insurance exist ")
          self.send_confirmation_email(
          self.request.user.id,
        )
        # Retourner la nouvelle assurance
        return Response(serializer.data, status=status.HTTP_200_OK)
   


    def post(self, request, *args, **kwargs):
        user = self.request.user
        
        if request.user.is_anonymous:
            raise PermissionDenied("You must be logged in to create an insurance policy.")
        
        if hasattr(request.user, 'insurance'):
            raise ValidationError("An insurance policy for this user already exists.")
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        insurance = serializer.save()
        if(self.request.user):
        
          print("user for insurance exist ")
          self.send_confirmation_email(
          self.request.user.id,
        )

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class TicketingServiceView(generics.RetrieveUpdateAPIView):
    serializer_class = TicketingServiceSerializer
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    def get_object(self):
        user = self.request.user
        ticketing = user.ticketing_services.first()
        if not ticketing:
            raise NotFound("Ticketing service does not exist")
        return ticketing
     
    def get(self, request, *args, **kwargs):
        ticketing_service = self.get_object()
        serializer = self.get_serializer(ticketing_service)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        ticketing_service = self.get_object()
        serializer = self.get_serializer(ticketing_service, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    def post(self, request, *args, **kwargs):
        user = self.request.user
        # Vérifie s'il existe déjà un service de réservation, sinon en créer une nouvelle
        ticketing_service = user.ticketing_services.first()
        if ticketing_service:
            # Si un enregistrement existe, on le met à jour
            serializer = self.get_serializer(ticketing_service, data=request.data)
        else:
            # Sinon, on crée un nouvel enregistrement
            serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ticketing_service = serializer.save()

        if not ticketing_service:
            self.send_confirmation_email(user.id, "Service de réservation Billet ")
            

        # Envoi de l'e-mail de confirmation
        # self.send_confirmation_email(user.id, "Service de réservation")
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    
    def send_confirmation_email(self, user_id, service_name):
        """
        Méthode pour envoyer une notification par e-mail lors de l'abonnement.
        """
        from django.core.mail import send_mail
        from django.contrib.auth import get_user_model
        User = get_user_model()

        try:
            user = User.objects.get(id=user_id)
            subject = "Confirmation de votre abonnement"
            body = f"Vous avez été abonné avec succès au service {service_name}."

            send_mail(
                subject=subject,
                message=body,
                from_email="no-reply@votreapp.com",
                recipient_list=[user.email],
            )
        except User.DoesNotExist:
            raise NotFound("Utilisateur introuvable pour envoyer l'e-mail.")    
        
    # Méthode pour supprimer des fichiers spécifiques
    def patch(self, request, *args, **kwargs):
        ticketing = self.get_object()  # Récupérer l'objet lié à l'utilisateur
        files_to_delete = request.data.get("files_to_delete", [])
        
        if not isinstance(files_to_delete, list):
            return Response({"error": "files_to_delete must be a list"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Supprimer les fichiers spécifiés
        for file_field in files_to_delete:
            if hasattr(ticketing.files, file_field):
                file = getattr(ticketing.files, file_field)
                if file:
                    # Supprimer physiquement le fichier du système de fichiers
                    file.delete(save=False)
                    # Supprimer la référence dans l'objet Files
                    setattr(ticketing.files, file_field, None)

        ticketing.files.save()  # Sauvegarder les modifications
        
        # Retourner une réponse de succès
        return Response({"message": "Fichiers supprimés avec succès"}, status=status.HTTP_200_OK)

            


    # def post(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     ticketing_service = serializer.save()
    #     return Response(serializer.data, status=status.HTTP_201_CREATED)

class ReferralViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    @action(detail=False, methods=['get'])
    def my_referral(self, request):
        referral, created = Referral.objects.get_or_create(user=request.user)
        serializer = ReferralSerializer(referral)
        return Response(serializer.data)

class SubscriptionPlanView(generics.ListAPIView):
    queryset = SubscriptionPlan.objects.all()
    serializer_class = SubscriptionPlanSerializer
    permission_classes = [AllowAny]

class UserSubscriptionView(generics.CreateAPIView):
    serializer_class = UserSubscriptionSerializer
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    def perform_create(self, serializer):
        plan_id = self.request.data.get('plan')
        try:
            plan = SubscriptionPlan.objects.get(id=plan_id)
        except SubscriptionPlan.DoesNotExist:
            raise NotFound(f"SubscriptionPlan with id {plan_id} does not exist")
        serializer.save(plan=plan)

class UserSubscriptionDetailView(generics.RetrieveAPIView):
    serializer_class = UserSubscriptionSerializer
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    def get_object(self):
        return self.request.user.subscription

class PaymentView(generics.ListAPIView):
    serializer_class = PaymentSerializer
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    def get_queryset(self):
        return Payment.objects.filter(user=self.request.user)

class ParentReferenceCodeView(generics.RetrieveAPIView):
    serializer_class = ParentReferenceCodeSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            student = Student.objects.get(user=request.user)
            serializer = self.get_serializer(student)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Student.DoesNotExist:
            return Response({"detail": "Student profile not found."}, status=status.HTTP_404_NOT_FOUND)


class ServiceAbonAPIView(APIView):
    permission_classes = [IsAuthenticated,IsStudentAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user

        # Count the number of services the user has
        service_count = (
            IrrevocablePaymentCertificate.objects.filter(user=user).count() +
            Insurance.objects.filter(user=user).count() +
            HousingSearch.objects.filter(user=user).count() +
            TicketingService.objects.filter(user=user).count()
        )

        return Response({
            "services_abon": service_count
        })

# Recuperation les fichiers dans les service abonne
class ServiceFilesAPIView(APIView):
    permission_classes = [IsAuthenticated, IsStudentAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user

        # Récupération des services liés à l'utilisateur
        irrevocable_payments = IrrevocablePaymentCertificate.objects.filter(user=user)
        insurances = Insurance.objects.filter(user=user)
        housing_searches = HousingSearch.objects.filter(user=user)
        ticketing_services = TicketingService.objects.filter(user=user)

        # Sérialisation des données
        irrevocable_serializer = IrrevocablePaymentCertificateSerializer(irrevocable_payments, many=True)
        insurance_serializer = InsuranceSerializer(insurances, many=True)
        housing_serializer = HousingSearchSerializer(housing_searches, many=True)
        ticketing_serializer = TicketingServiceSerializer(ticketing_services, many=True)

        # Extraction des fichiers uniquement
        services_files = {
            "irrevocable_payments": [item.get("files") for item in irrevocable_serializer.data],
            "insurances": [item.get("files") for item in insurance_serializer.data],
            "housing": [item.get("files") for item in housing_serializer.data],
            "ticketing": [item.get("files") for item in ticketing_serializer.data],
        }

        return Response({
            "services_files": services_files
        })
