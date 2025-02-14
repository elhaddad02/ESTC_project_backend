from rest_framework import serializers
from .models import *
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from authentication.models import User, Parent, Student
from django.core.exceptions import PermissionDenied
from authentication.utils import Util
from students.models import HousingSearch, Insurance, File, PaymentMethod, Payment,IrrevocablePaymentCertificate, TicketingService
from students.serializers import FileSerializer as FS

from rest_framework_simplejwt.tokens import RefreshToken
from django.urls import reverse

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['preliminary_acceptance', 'payment_proof', 'passport_copy', 'additional_pdf']
        ref_name = 'ParentFile'
                
class ParentRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email')
    username = serializers.CharField(source='user.username', required=False)
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    country_code = serializers.CharField(source='user.country_code', required=False)
    phone_number = serializers.CharField(source='user.phone_number', required=False)
    country = serializers.CharField(source='user.country', required=False)
    date_of_birth = serializers.DateField(source='user.date_of_birth', required=False)
    town = serializers.CharField(source='user.town', required=False)
    reference_code = serializers.UUIDField(write_only=True,)
    gender = serializers.CharField(source='user.gender', required=False)

    class Meta:
        model = Parent
        fields = [
            'username', 'email', 'password', 'first_name', 'last_name',
            'country_code', 'phone_number', 'country', 'date_of_birth',
            'town', 'reference_code', 'gender'
        ]

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('This email is already in use')
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError('This username is already in use')
        return value

    def create(self, validated_data):
        # Extraire les données
        user_data = validated_data.pop('user')
        reference_code = validated_data.pop('reference_code', None)
        password = validated_data.pop('password')

        # Vérifier le code de référence avant de créer l'utilisateur
        if reference_code:
            try:
                student = Student.objects.get(parent_reference_code=reference_code)
            except Student.DoesNotExist:
                raise serializers.ValidationError({"reference_code": "Invalid parent reference code."})
        else:
            raise serializers.ValidationError({"reference_code": "Parent reference code is required."})

        # Créer l'utilisateur
        user = User.objects.create_user(
            email=user_data['email'],
            password=password,
            role='parent',
            first_name=user_data.get('first_name'),
            last_name=user_data.get('last_name'),
            country_code=user_data.get('country_code'),
            phone_number=user_data.get('phone_number'),
            country=user_data.get('country'),
            date_of_birth=user_data.get('date_of_birth'),
            town=user_data.get('town'),
            gender=user_data.get('gender')
        )

        # Créer le parent
        parent = Parent.objects.create(user=user)

        # Lier le parent à l'étudiant
        student.parents.add(parent)
        student.save()

        # Envoyer un email de vérification
        request = self.context.get('request')
        domaine = "https://app.universfrancesucces.com"
        # domaine = "http://localhost:8000"

        token = RefreshToken.for_user(user).access_token
        # uidb64 = urlsafe_base64_encode(force_bytes(user.id))  # Encodage sécurisé
        relative_link = reverse('email-verify')
        abs_url = f'{domaine}{relative_link}?token={token}'

        Util.send_email_verification(user, abs_url)     
    
        return parent


class IrrevocablePaymentCertificateSerializer(serializers.ModelSerializer):
   
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    phone_number = serializers.CharField(source='user.phone_number', required=False)
    place_of_birth = serializers.CharField(source='user.town', required=False)
    date_of_birth = serializers.DateField(source='user.date_of_birth', required=False)
    email = serializers.EmailField(source='user.email', required=False)
    nationality = serializers.CharField(source='user.nationality', required=False)
    country_code = serializers.CharField(source='user.country_code', required=False)
    country = serializers.CharField(source='user.country', required=False)

    # Fields related to the user's student information
    accepted_university = serializers.CharField(source='user.student.accepted_university', allow_null=True, allow_blank=True, required=False)
    accepted_program = serializers.CharField(source='user.student.accepted_program', allow_null=True, allow_blank=True, required=False)
    accepted_level = serializers.CharField(source='user.student.accepted_level', allow_null=True, allow_blank=True, required=False)
    destination_city = serializers.CharField(source='user.student.destination_city', allow_null=True, allow_blank=True, required=False)
    destination_country = serializers.CharField(source='user.student.destination_country', allow_null=True, allow_blank=True, required=False)

    # Files related to the certificate
    files = FS(required=False)

    class Meta:
        model = IrrevocablePaymentCertificate
        fields = [
            'first_name', 'last_name', 'phone_number', 'place_of_birth', 'date_of_birth',
            'email', 'nationality', 'country_code', 'country', 'accepted_university',
            'accepted_program', 'accepted_level', 'destination_city', 'destination_country', 
            'files'
        ]
        ref_name = 'ParentIrrevocablePaymentCertificate' 
    

class ParentProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email', required=False)
    username = serializers.CharField(source='user.username', required=False)
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    country_code = serializers.CharField(source='user.country_code', required=False)
    phone_number = serializers.CharField(source='user.phone_number', required=False)
    country = serializers.CharField(source='user.country', required=False)
    date_of_birth = serializers.DateField(source='user.date_of_birth', required=False)
    town = serializers.CharField(source='user.town', required=False)
    nationality = serializers.CharField(source='user.nationality', required=False)
    picture = serializers.ImageField(source='user.picture', required=False)
    completion_rate = serializers.SerializerMethodField(method_name='get_completion_rate', required=False, read_only=True)
    completion_message = serializers.SerializerMethodField(method_name='get_completion_message', required=False, read_only=True)

    class Meta:
        model = Parent
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'country_code', 'phone_number', 'country', 'date_of_birth',
            'town', 'nationality', 'picture',
            'completion_rate',
            'completion_message'
        ]

    def get_completion_rate(self, obj):
        required_fields = [
            'username', 'email', 'first_name', 'last_name',
            'country_code', 'phone_number', 'country', 'date_of_birth',
            'town', 'nationality', 'picture'
        ]
        completed_fields = sum(1 for field in required_fields if getattr(obj.user, field, None))
        return round(completed_fields / len(required_fields), 2) * 100

    def get_completion_message(self, obj):
        completion_rate = self.get_completion_rate(obj) / 100
        if completion_rate < 0.5:
            return "Veuillez compléter votre profil pour une expérience optimale."
        elif completion_rate < 0.9:
            return "Vous êtes proche de compléter votre profil !"
        else:
            return "Félicitations ! Votre profil est maintenant complet."

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        changed_fields = [self.get_field_name(attr) for attr, value in user_data.items() if getattr(instance.user, attr) != value]

        if len(changed_fields) == 0:
            pass

        elif changed_fields:
            for attr, value in user_data.items():
                setattr(instance.user, attr, value)
            instance.user.save()

            if len(changed_fields) <= 3:
                message = f"Votre profil a été mis à jour avec succès. Les champs suivants ont été modifiés: {', '.join(changed_fields)}."
                message_admin = f"Profil Parent \"{instance.user.first_name} {instance.user.last_name}\" mis à jour avec succès. Champs modifiés: {', '.join(changed_fields)}."
            else:
                message = f"Votre profil a été mis à jour avec succès ({len(changed_fields)} champ(s) modifié(s))."
                message_admin = f"Profil Parent \"{instance.user.first_name} {instance.user.last_name}\" mis à jour avec succès ({len(changed_fields)} champ(s) modifié(s))."

            send_notification(
                user=instance.user,
                message=message,
                notification_type="Profile Update"
            )

            admin_notification=message_admin
            self.send_notification_to_admins(admin_notification, f"{instance.user.first_name} {instance.user.last_name}", instance.user.id)

        return super().update(instance, validated_data)
    
    def get_field_name(self, field_name):
        field_mapping = {
            'first_name': 'Prénom',
            'last_name': 'Nom',
            'email': 'Adresse e-mail',
            'phone_number': 'Numéro de téléphone',
            'country_code': 'Code pays',
            'country': 'Pays',
            'date_of_birth': 'Date de naissance',
            'town': 'Ville de naissance',
            'nationality': 'Nationalité',
            'picture': 'Photo de profil',
        }
        return field_mapping.get(field_name, field_name)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = {
            'username': instance.user.username,
            'email': instance.user.email,
            'role': instance.user.role,
        }
        return representation
    
    
    def send_notification_to_admins(self, message, student_name, student_id):
                admins = User.objects.filter(role='admin')
                for admin in admins:
                    send_notification(admin, f"{message}", 'admin_notification')
    
class ChildProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email')
    username = serializers.CharField(source='user.username')
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    country_code = serializers.CharField(source='user.country_code', required=False)
    phone_number = serializers.CharField(source='user.phone_number', required=False)
    country = serializers.CharField(source='user.country', required=False)
    date_of_birth = serializers.DateField(source='user.date_of_birth', required=False)
    town = serializers.CharField(source='user.town', required=False)
    nationality = serializers.CharField(source='user.nationality', required=False)
    picture = serializers.ImageField(source='user.picture', required=False)

    class Meta:
        model = Student
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'country_code', 'phone_number', 'country', 'date_of_birth',
            'town', 'nationality', 'picture'
        ]

class ChildHousingSearchSerializer(serializers.ModelSerializer):
    files = FileSerializer(required=False)

    class Meta:
        model = HousingSearch
        fields = [
            'accommodation_type', 'preferred_location', 'move_in_date', 'stay_duration', 'budget',
            'special_needs', 'purpose_of_stay', 'number_of_occupants', 'university_or_workplace',
            'address', 'rental_contract', 'renewal_date', 'files'
        ]
        
class ChildHousingStatusSerializer(serializers.ModelSerializer):
    student = ChildProfileSerializer(source='user.student')
    housing_search = ChildHousingSearchSerializer(source='*')

    class Meta:
        model = HousingSearch
        fields = ['student', 'housing_search']       
 
class ChildTicketingSerializer(serializers.ModelSerializer):
    files = FileSerializer(required=False)

    class Meta:
        model = TicketingService
        fields = [
            'departure_country', 'departure_city','destination_country', 'destination_city',
            'departure_date', 'return_date', 'number_of_passengers', 'travel_class',
            'preferred_airlines', 'special_requests', 'files'
        ]
        
class ChildTicketingStatusSerializer(serializers.ModelSerializer):
    student = ChildProfileSerializer(source='user.student')
    ticketing = ChildTicketingSerializer(source='*')

    class Meta:
        model = TicketingService
        fields = ['student', 'ticketing']       
 

class ChildPaymentSerializer(serializers.ModelSerializer):
    method_type = serializers.CharField(source='method.payment_method', read_only=True)
    service_name = serializers.CharField(read_only=True)

    class Meta:
        model = Payment
        fields = ['id', 'service_name', 'date', 'method_type', 'status', 'amount']

class PaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = ['card_number', 'expiration_date', 'cvv']
        
class ChildPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['id', 'user', 'service_name', 'date', 'method', 'status', 'amount']

class InsuranceSerializer(serializers.ModelSerializer):
    files = FileSerializer(required=False)
    payment_method = PaymentMethodSerializer(required=False)

    class Meta:
        model = Insurance
        fields = [
            'id', 'start_date', 'insurance_duration', 'insurance_type', 
            'beneficiaries', 'insured_amount', 'files', 'payment_method', 'expiry_date'
        ]

    def create(self, validated_data):
        files_data = validated_data.pop('files', None)
        payment_method_data = validated_data.pop('payment_method', None)
        user = self.context['request'].user

        if user.is_anonymous:
            raise PermissionDenied("You must be logged in to create an insurance policy.")

        insurance = Insurance.objects.create(user=user, **validated_data)

        if files_data:
            files = File.objects.create(**files_data)
            insurance.files = files
            insurance.save()

        if payment_method_data:
            payment_method = PaymentMethod.objects.create(user=user, **payment_method_data)
            insurance.payment_method = payment_method
            insurance.save()
        send_notification(user, "Votre police d'assurance a été créée avec succès.", "insurance")
        return insurance

    def update(self, instance, validated_data):
        files_data = validated_data.pop('files', None)
        payment_method_data = validated_data.pop('payment_method', None)
        user = self.context['request'].user

        if instance.user != user:
            raise PermissionDenied("You cannot update this insurance policy.")

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if files_data:
            files_serializer = FileSerializer(instance.files, data=files_data)
            if files_serializer.is_valid():
                files_serializer.save()

        if payment_method_data:
            if instance.payment_method:
                payment_method_serializer = PaymentMethodSerializer(instance.payment_method, data=payment_method_data)
                if payment_method_serializer.is_valid():
                    payment_method_serializer.save()
            else:
                payment_method = PaymentMethod.objects.create(user=user, **payment_method_data)
                instance.payment_method = payment_method
                instance.save()
        send_notification(user, "Votre police d'assurance a été mise à jour avec succès.", "insurance")
        return instance
    
# class ChildCandidateSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Candidate
#         fields = [
#             'nom_du_candidat', 'prenom_du_candidat', 'email',
#             'date_de_naissance', 'lieu_de_naissance', 
#             'statut_du_candidat', 'acceptation', 'candidat_universitaire', 
#             'annee_scolaire', 'sexe', 'guichet', 'numero_compte', 'cle_rib',
#             'date_de_validite', 'identifiant_etudiant_ufs', 'compte_bancaire', 'bic'
#         ]
        


class SendEmailSerializer(serializers.Serializer):
    subject = serializers.CharField(max_length=255)
    body = serializers.CharField()
    recipient_ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=False
    )

    def validate_recipient_ids(self, value):
        if not User.objects.filter(id__in=value).exists():
            raise serializers.ValidationError("One or more user IDs are invalid.")
        return value



def send_notification(user, message, notification_type):
    Notification.objects.create(
        user=user,
        message=message,
        notification_type=notification_type
    )
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'notifications_{user.username}', {
            'type': 'send_notification',
            'message': message,
        }
    )
