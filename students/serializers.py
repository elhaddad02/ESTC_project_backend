from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.core.exceptions import PermissionDenied
from rest_framework import serializers

from authentication.models import Student, User
from authentication.utils import Util
from datetime import date
from rest_framework_simplejwt.tokens import RefreshToken
from django.urls import reverse
from urllib.parse import urlparse


from .models import *

class PaymentSerializer(serializers.ModelSerializer):
    method_type = serializers.CharField(source='method.payment_method', read_only=True)
    service_name = serializers.CharField(read_only=True)

    class Meta:
        model = Payment
        fields = ['id', 'service_name', 'date', 'method_type', 'status', 'amount']

    def create(self, validated_data):
        user = self.context['request'].user

        if user.is_anonymous:
            raise PermissionDenied("You must be logged in to make a payment.")

        payment = Payment.objects.create(user=user, **validated_data)
        return payment


class PaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = [
            'id', 'type','carte_card_number', 'carte_expiration_date', 'carte_cvv','virement_banque_nom','virement_iban','virement_bic_swift','virement_code_bancaire'
        ]

def send_notification(user, message, notification_type):
    # Notification.objects.create(
    #     user=user,
    #     message=message,
    #     notification_type=notification_type
    # )
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'notifications_{user.username}', {
            'type': 'send_notification',
            'message': message,
        }
    )


class ReferralSerializer(serializers.ModelSerializer):
    referred_users = serializers.StringRelatedField(many=True, read_only=True)

    class Meta:
        model = Referral
        fields = ['code', 'credit', 'referred_users']
        read_only_fields = ['code', 'credit', 'referred_users']


class GuardianSerializer(serializers.ModelSerializer):
    class Meta:
        model = Guardian
        fields = [
            'father_name', 'mother_name', 'father_email', 'mother_email',
            'father_country_code', 'father_phone_number', 'mother_country_code', 'mother_phone_number'
        ]


class ProgramSerializer(serializers.ModelSerializer):
    class Meta:
        model = Program
        fields = [
            'last_degree_obtained', 'destination_city', 'destination_country',
            'desired_sector', 'university_institution', 'academic_year', 'accepted_program'
        ]

class StudentRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email')
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField(source='user.first_name', required=False)
    gender = serializers.CharField(source='user.gender', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    country_code = serializers.CharField(source='user.country_code', required=False)
    phone_number = serializers.CharField(source='user.phone_number', required=False)
    country = serializers.CharField(source='user.country', required=False)
    date_of_birth = serializers.DateField(source='user.date_of_birth', required=False)
    town = serializers.CharField(source='user.town', required=False)
    school_year = serializers.CharField(source='user.school_year', required=False)
    university = serializers.CharField(source='user.university', required=False)
    referred_by_code = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Student
        fields = [
            'email', 'password', 'first_name', 'last_name',
            'country_code', 'phone_number', 'country', 'date_of_birth',
            'town', 'referred_by_code','gender', 'school_year', 'university'
        ]

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('This email is already in use')
        return value

    def create(self, validated_data):
        referred_by_code = validated_data.pop('referred_by_code', None)
        user_data = validated_data.pop('user')
        email = user_data['email']
        password = validated_data.pop('password')

        user = User.objects.create_user(
            email=email,
            password=password,
            role='student',
            first_name=user_data.get('first_name'),
            last_name=user_data.get('last_name'),
            country_code=user_data.get('country_code'),
            phone_number=user_data.get('phone_number'),
            country=user_data.get('country'),
            date_of_birth=user_data.get('date_of_birth'),
            town=user_data.get('town'),
            gender=user_data.get('gender'),
            school_year=user_data.get('school_year'),
            university=user_data.get('university')
        )

        student = Student.objects.create(user=user)

        if referred_by_code:
            try:
                referral = Referral.objects.get(code=referred_by_code)
                referral.referred_users.add(user)
                referral.reward_referrer(amount=50.0)
                referral.save()
            except Referral.DoesNotExist:
                pass
        request = self.context.get('request')
        domaine = "https://app.universfrancesucces.com"
        # domaine = "http://localhost:8000"

        token = RefreshToken.for_user(user).access_token
        # uidb64 = urlsafe_base64_encode(force_bytes(user.id))  # Encodage sécurisé
        relative_link = reverse('email-verify')
        abs_url = f'{domaine}{relative_link}?token={token}'

        Util.send_email_verification(user, abs_url)     
    
        return student



class StudentProfileSerializer(serializers.ModelSerializer):
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
    guardian = GuardianSerializer(required=False)
    program = ProgramSerializer(required=False)
    completion_percentage = serializers.SerializerMethodField()
    
    class Meta:
        model = Student
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'country_code', 'phone_number', 'country', 'date_of_birth',
            'town', 'nationality', 'picture', 'guardian', 'program','completion_percentage'
        ]

    def create(self, validated_data):
        user_data = validated_data.pop('user')
        guardian_data = validated_data.pop('guardian', None)
        program_data = validated_data.pop('program', None)

        user = User.objects.create(**user_data)
        
        student = Student.objects.create(user=user, **validated_data)

        if guardian_data:
            Guardian.objects.create(student=student, **guardian_data)
        if program_data:
            Program.objects.create(student=student, **program_data)
            
        message= "Votre profil étudiant a été créé avec succès."    
        send_notification(user,message, 'student_profile_created')
        self.send_notification_to_parents(user, "Votre enfant a mis créé son profil étudiant.")
        admin_notification=f"Un nouveau profil étudiant a été créé."
        self.send_notification_to_admins(admin_notification, f"{user.first_name} {user.last_name}", user.id)
        return student
    


    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        changed_fields = []

        for attr, value in user_data.items():
            if getattr(instance.user, attr) != value:
                changed_fields.append(attr)
                setattr(instance.user, attr, value)
        instance.user.save()

        guardian_data = validated_data.pop('guardian', None)
        if guardian_data:
            guardian, created = Guardian.objects.get_or_create(student=instance)
            guardian_changed_fields = []
            for attr, value in guardian_data.items():
                if getattr(guardian, attr) != value:
                    guardian_changed_fields.append(attr)
                    setattr(guardian, attr, value)
            guardian.save()
            changed_fields.extend(guardian_changed_fields)

        program_data = validated_data.pop('program', None)
        if program_data:
            program, created = Program.objects.get_or_create(student=instance)
            program_changed_fields = []
            for attr, value in program_data.items():
                if getattr(program, attr) != value:
                    program_changed_fields.append(attr)
                    setattr(program, attr, value)
            program.save()
            changed_fields.extend(program_changed_fields)


        for attr, value in validated_data.items():
            if getattr(instance, attr) != value:
                changed_fields.append(attr)
                setattr(instance, attr, value)
        instance.save()

        field_names = [self.get_field_name(field) for field in changed_fields]
        field_names = [self.get_field_name(field) for field in changed_fields]

        if len(changed_fields) == 0:
            pass
        elif len(changed_fields) <= 3:
            message_user = f"Votre profil étudiant a été mis à jour avec succès. Champ(s) mis à jour : {', '.join(field_names)}"
            message_parent = f"Votre enfant, {instance.user.first_name} {instance.user.last_name}, a mis à jour son profil étudiant avec les champs : {', '.join(field_names)}."
            message_admin = f"Profil étudiant mis à jour pour {instance.user.first_name} {instance.user.last_name}. Champ(s) mis à jour : {', '.join(field_names)}."
        else:
            message_user = f"Votre profil étudiant a été mis à jour avec succès. Vous avez modifié plus de {len(changed_fields)} champs."
            message_parent = f"Votre enfant, {instance.user.first_name} {instance.user.last_name}, a mis à jour son profil étudiant avec plusieurs changements."
            message_admin = f"Profil étudiant mis à jour pour {instance.user.first_name} {instance.user.last_name} avec plusieurs changements."

        if 'message_user' in locals():
            send_notification(instance.user, message_user, 'student_profile_updated')
            self.send_notification_to_parents(instance.user, message_parent)
            self.send_notification_to_admins(message_admin, f"{instance.user.first_name}")


        return instance

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
            'mother_name':'Nom de la mère',
            'mother_country_code' : 'Code pays (mère)',
            'mother_phone_number' : 'Numéro de téléphone (mère)',
            'father_name' : 'Nom du père',
            'father_country_code' : 'Code pays (père)',
            'father_phone_number' : 'Numéro de téléphone (père)',
            'father_email':'E-mail du père',
            'mother_email':'E-mail du mère',
            'academic_year' : 'Année scolaire',
            'destination_city' : 'Ville cible',
            'desired_sector' :"Domaine d'intérêt",
            'university_institution' : 'Institution universitaire',
            'last_degree_obtained' : 'Diplôme le plus récent',
            'destination_country' : 'Pays cible',
        }
        return field_mapping.get(field_name, field_name)
    
    def get_completion_percentage(self, obj):
        total_fields = [
            obj.user.username,
            obj.user.email,
            obj.user.first_name,
            obj.user.last_name,
            obj.user.country_code,
            obj.user.phone_number,
            obj.user.country,
            obj.user.date_of_birth,
            obj.user.town,
            obj.user.nationality
        ]

        # Check non-null fields inside the guardian object
        if obj.guardian:
            total_fields += [
                obj.guardian.father_name,
                obj.guardian.mother_name,
                obj.guardian.father_email,
                obj.guardian.mother_email,
                obj.guardian.father_phone_number,
                obj.guardian.mother_phone_number
            ]

        # Check non-null fields inside the program object
        if obj.program:
            total_fields += [
                obj.program.last_degree_obtained,
                obj.program.destination_city,
                obj.program.destination_country,
                obj.program.desired_sector,
                obj.program.university_institution,
                obj.program.academic_year,

            ]
        
        # Count only non-null fields
        filled_fields = [field for field in total_fields if field]
        
        # Calculate the percentage of filled fields
        percentage = (len(filled_fields) / len(total_fields)) * 100

        return round(percentage, 2)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = {
            'username': instance.user.username,
            'email': instance.user.email,
            'role': instance.user.role,
        }
        return representation
    
    def send_notification_to_parents(self, user, message):
        for parent in user.student.parents.all():
            send_notification(parent.user, message, 'parent_notification')
            
    def send_notification_to_admins(self, message, first_name):
        admins = User.objects.filter(role='admin')
        for admin in admins:
            send_notification(admin, f"{message} {first_name}", 'admin_notification')


class FileSerializer(serializers.ModelSerializer):
    preliminary_acceptance = serializers.FileField(required=False, allow_null=True)
    preliminary_acceptance_url = serializers.URLField(required=False, allow_null=True, allow_blank=True)
    payment_proof = serializers.FileField(required=False, allow_null=True)
    payment_proof_url = serializers.URLField(required=False, allow_null=True, allow_blank=True)
    passport_copy = serializers.FileField(required=False, allow_null=True)
    passport_copy_url = serializers.URLField(required=False, allow_null=True, allow_blank=True)
    additional_pdf = serializers.FileField(required=False, allow_null=True)
    additional_pdf_url = serializers.URLField(required=False, allow_null=True, allow_blank=True)

    class Meta:
        model = File
        fields = [
            'preliminary_acceptance', 'preliminary_acceptance_url',
            'payment_proof', 'payment_proof_url',
            'passport_copy', 'passport_copy_url',
            'additional_pdf', 'additional_pdf_url'
        ]

    def validate(self, data):
        file_types = ['preliminary_acceptance', 'payment_proof', 'passport_copy', 'additional_pdf']

        for file_type in file_types:
            file_field = data.get(file_type)
            url_field = data.get(f'{file_type}_url')

            if file_field and url_field:
                raise serializers.ValidationError(
                    f"Cannot provide both file and URL for {file_type}"
                )
            if not file_field and not url_field:
                continue  # Vous pouvez décider de traiter cette situation si nécessaire

        return data





    def create(self, validated_data):
        try:
            file_instance = File.objects.create(**validated_data)
            return file_instance
        except Exception as e:
            raise serializers.ValidationError(f"Error creating file: {str(e)}")

    def update(self, instance, validated_data):
        try:
            for attr, value in validated_data.items():
                setattr(instance, attr, value)
            instance.save()
            return instance
        except Exception as e:
            raise serializers.ValidationError(f"Error updating file: {str(e)}")


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
    accepted_university = serializers.CharField(source='user.student.accepted_university', allow_null=True, allow_blank=True, required=False)
    accepted_program = serializers.CharField(source='user.student.accepted_program', allow_null=True, allow_blank=True, required=False)
    accepted_level = serializers.CharField(source='user.student.accepted_level', allow_null=True, allow_blank=True, required=False)
    destination_city = serializers.CharField(source='user.student.destination_city', allow_null=True, allow_blank=True, required=False)
    destination_country = serializers.CharField(source='user.student.destination_country', allow_null=True, allow_blank=True, required=False)
    files = FileSerializer(required=False)

    class Meta:
        model = IrrevocablePaymentCertificate
        fields = [
            'id', 'first_name', 'last_name', 'phone_number', 'place_of_birth', 'date_of_birth',
            'email', 'nationality', 'country_code', 'country', 'accepted_university', 'accepted_program',
            'accepted_level', 'destination_city', 'destination_country', 'files'
        ]

    def create(self, validated_data):
        user = self.context['request'].user

        if user.is_anonymous:
            raise PermissionDenied("Vous devez être connecté pour créer un certificat.")

        files_data = validated_data.pop('files', None)
        user_data = validated_data.pop('user', {})
        student_data = user_data.pop('student', {})

        # Update or create user
        for attr, value in user_data.items():
            setattr(user, attr, value)
        user.save()

        # Update or create student
        student, _ = Student.objects.get_or_create(user=user)
        for attr, value in student_data.items():
            setattr(student, attr, value)
        student.save()

        # Handle files creation (only if files_data exists)
        if files_data:
            files = File.objects.create(**files_data)
            certificate = IrrevocablePaymentCertificate.objects.create(user=user, files=files)
        else:
            certificate = IrrevocablePaymentCertificate.objects.create(user=user)

        # Send notification
        message = "Vous avez créé un certificat de paiement irrévocable avec succès."
        send_notification(user, message, 'certificate_created')
        self.send_notification_to_parents(user, "Votre enfant a créé un certificat de paiement irrévocable.")
        admin_notification="Un certificat de paiement irrévocable a été créé."
        self.send_notification_to_admins(admin_notification, f"{user.first_name} {user.last_name}", user.id)
        return certificate

    def update(self, instance, validated_data):
        user = self.context['request'].user

        # Permission check
        if user.is_anonymous or instance.user != user:
            raise PermissionDenied("Vous ne pouvez pas mettre à jour ce certificat.")

        files_data = validated_data.pop('files', None)
        user_data = validated_data.pop('user', {})
        student_data = user_data.pop('student', {})

        changed_fields = {
            'user': [],
            'student': [],
            'certificate': []
        }

        # Update user
        for attr, value in user_data.items():
            if getattr(user, attr) != value:
                changed_fields['user'].append(attr)
                setattr(user, attr, value)
        user.save()

        # Update student
        student, _ = Student.objects.get_or_create(user=user)
        for attr, value in student_data.items():
            if getattr(student, attr) != value:
                changed_fields['student'].append(attr)
                setattr(student, attr, value)
        student.save()

        # Handle file data
        if files_data:
            if instance.files:
                files_serializer = FileSerializer(instance.files, data=files_data)
                if files_serializer.is_valid():
                    files_serializer.save()
                    changed_fields['certificate'].append('files')
            else:
                files = File.objects.create(**files_data)
                instance.files = files
                changed_fields['certificate'].append('files')

        # Update other fields
        for attr, value in validated_data.items():
            if getattr(instance, attr) != value:
                changed_fields['certificate'].append(attr)
                setattr(instance, attr, value)
        instance.save()

        # Prepare notification message
        new_name = f"{user.first_name} {user.last_name}"
        all_changed_fields = [field for fields in changed_fields.values() for field in fields]
        
        if len(all_changed_fields) == 0:
            pass
        elif len(all_changed_fields) <= 3:
            field_names = [self.get_field_name(field) for field in all_changed_fields]
            message_user = f"Votre certificat a été mis à jour avec succès. Champ(s) mis à jour : {', '.join(field_names)}"
            message_parent = f"Votre enfant, {new_name}, a mis à jour son certificat avec les champs : {', '.join(field_names)}."
            message_admin = f"Certificat mis à jour pour {new_name} : {', '.join(field_names)}."
        else:
            message_user = f"Votre certificat a été mis à jour avec succès. Vous avez modifié plus de 3 champs."
            message_parent = f"Votre enfant, {new_name}, a mis à jour son certificat avec plusieurs changements."
            message_admin = f"Certificat mis à jour pour {new_name} avec plusieurs changements."

        if len(all_changed_fields) > 0:
            send_notification(instance.user, message_user, 'certificate_updated')
            self.send_notification_to_parents(instance.user, message_parent)
            self.send_notification_to_admins(message_admin, new_name, instance.user.id)

        return instance

    def get_field_name(self, field_name):
        field_mapping = {
            'first_name': 'Prénom',
            'last_name': 'Nom',
            'phone_number': 'Numéro de téléphone',
            'town': 'Lieu de naissance',
            'date_of_birth': 'Date de naissance',
            'email': 'Adresse e-mail',
            'nationality': 'Nationalité',
            'country_code': 'Code pays',
            'country': 'Pays',
            'accepted_university': 'Université acceptée',
            'accepted_program': 'Programme accepté',
            'accepted_level': 'Niveau accepté',
            'destination_city': 'Ville de destination',
            'destination_country': 'Pays de destination',
            'files': 'Fichiers'
        }
        return field_mapping.get(field_name, field_name)

    def send_notification_to_parents(self, user, message):
        for parent in user.student.parents.all():
            send_notification(parent.user, message, 'parent_notification')
            
    def send_notification_to_admins(self, message, student_name, student_id):
        admins = User.objects.filter(role='admin')
        for admin in admins:
            send_notification(admin, f"{message} ", 'admin_notification')



class InsuranceSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    phone_number = serializers.CharField(source='user.phone_number', required=False)
    place_of_birth = serializers.CharField(source='user.town', required=False)
    date_of_birth = serializers.DateField(source='user.date_of_birth', required=False)
    email = serializers.EmailField(source='user.email', required=False)
    nationality = serializers.CharField(source='user.nationality', required=False)
    country_code = serializers.CharField(source='user.country_code', required=False)
    country = serializers.CharField(source='user.country', required=False)
    files = FileSerializer(required=False)
    payment_method = PaymentMethodSerializer(required=False)

    class Meta:
        model = Insurance
        fields = [
            'id', 'first_name', 'last_name', 'phone_number', 'place_of_birth', 'date_of_birth',
            'email', 'nationality', 'country_code', 'country', 'start_date', 'insurance_duration',
            'insurance_type', 'beneficiaries', 'insured_amount', 'files', 'payment_method'
        ]

    def create(self, validated_data):
        files_data = validated_data.pop('files', None)
        payment_method_data = validated_data.pop('payment_method', None)
        user_data = validated_data.pop('user', {})

        user = self.context['request'].user

        if user.is_anonymous:
            raise PermissionDenied("You must be logged in to create an insurance policy.")

        for attr, value in user_data.items():
            setattr(user, attr, value)
        user.save()

        insurance = Insurance.objects.create(user=user, **validated_data)

        if files_data:
            files = File.objects.create(**files_data)
            insurance.files = files
            insurance.save()

        if payment_method_data:
            payment_method = PaymentMethod.objects.create(user=user, **payment_method_data)
            insurance.payment_method = payment_method
            insurance.save()

        # Create a payment record for the insurance
        default_payment_method = PaymentMethod.objects.filter(user=user).first()
        if default_payment_method:
            Payment.objects.create(
                user=user,
                service_name='Insurance Payment',
                method=default_payment_method,
                status='pending',  # or 'completed' based on your logic
                amount=validated_data['insured_amount']
            )

        # Send notification
        send_notification(user, f'Insurance policy {insurance.insurance_type} has been created.', 'insurance')

        return insurance

    def update(self, instance, validated_data):
        files_data = validated_data.pop('files', None)
        payment_method_data = validated_data.pop('payment_method', None)
        user_data = validated_data.pop('user', {})

        user = self.context['request'].user

        if instance.user != user:
            raise PermissionDenied("You cannot update this insurance policy.")

        if user_data:
            for attr, value in user_data.items():
                setattr(user, attr, value)
            user.save()

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

        # Update the payment record if necessary
        default_payment_method = PaymentMethod.objects.filter(user=user).first()
        if default_payment_method:
            Payment.objects.update_or_create(
                user=user,
                service_name='Insurance Payment',
                defaults={
                    'method': default_payment_method,
                    'status': 'success',  # or 'pending' based on your logic
                    'amount': validated_data['insured_amount']
                }
            )

        # Send notification
        send_notification(user, f'Insurance policy {instance.insurance_type} has been updated.', 'insurance')

        return instance


class HousingSearchSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    phone_number = serializers.CharField(source='user.phone_number', required=False)
    place_of_birth = serializers.CharField(source='user.town', required=False)
    date_of_birth = serializers.DateField(source='user.date_of_birth', required=False)
    email = serializers.EmailField(source='user.email', required=False)
    nationality = serializers.CharField(source='user.nationality', required=False)
    country_code = serializers.CharField(source='user.country_code', required=False)
    country = serializers.CharField(source='user.country', required=False)
    files = FileSerializer(required=False)

    class Meta:
        model = HousingSearch
        fields = [
            'id', 'first_name', 'last_name', 'phone_number', 'place_of_birth', 'date_of_birth',
            'email', 'nationality', 'country_code', 'country', 'accommodation_type', 'preferred_location',
            'move_in_date', 'stay_duration', 'budget', 'special_needs', 'purpose_of_stay', 'number_of_occupants',
            'university_or_workplace', 'files'
        ]

    def create(self, validated_data):
        files_data = validated_data.pop('files', None)
        user_data = validated_data.pop('user', {})

        user = self.context['request'].user

        if user.is_anonymous:
            raise PermissionDenied("You must be logged in to create a housing search.")

        for attr, value in user_data.items():
            setattr(user, attr, value)
        user.save()

        housing_search = HousingSearch.objects.create(user=user, **validated_data)

        if files_data:
            files = File.objects.create(**files_data)
            housing_search.files = files
            housing_search.save()

        message="Votre recherche de logement a été créé avec succès."
        send_notification(user,message , 'housing_search_created')
        self.send_notification_to_parents(user,"Votre enfant a créé une nouvelle recherche de logement.")
        admin_notification="Un recherche de logement a été créé."
        self.send_notification_to_admins(admin_notification, f"{user.first_name} {user.last_name}", user.id)
        
        return housing_search

    def update(self, instance, validated_data):
        files_data = validated_data.pop('files', None)
        user_data = validated_data.pop('user', {})

        user = self.context['request'].user

        if instance.user != user:
            raise PermissionDenied("You cannot update this housing search.")

        changed_fields = {}

        if user_data:
            for attr, value in user_data.items():
                if getattr(user, attr) != value:
                    changed_fields[f"user.{attr}"] = value
                setattr(user, attr, value)
            user.save()


        if files_data:
            files_serializer = FileSerializer(instance.files, data=files_data)
            if files_serializer.is_valid():
                files_serializer.save()
                changed_fields['files'] = 'Mis à jour'


        for attr, value in validated_data.items():
            if getattr(instance, attr) != value:
                changed_fields[attr] = value
            setattr(instance, attr, value)
        instance.save()


        if changed_fields:
            field_names = [self.get_field_name(field) for field in changed_fields.keys()]
            if len(changed_fields) == 0:
                pass
            elif len(changed_fields) <= 3:
                message_user = f"Votre recherche de logement a été mise à jour. Champ(s) mis à jour : {', '.join(field_names)}"
                message_parent = f"Votre enfant a mis à jour sa recherche de logement : {', '.join(field_names)}."
                message_admin = f"Recherche de logement mise à jour pour {instance.user.first_name} {instance.user.last_name}. Champ(s) mis à jour: {', '.join(field_names)}."
            else:
                message_user = f"Votre recherche de logement a été mise à jour. Vous avez modifié plus de 3 champs."
                message_parent = f"Votre enfant a mis à jour sa recherche de logement avec plusieurs changements."
                message_admin = f"Recherche de logement mise à jour pour {instance.user.first_name} {instance.user.last_name} avec plusieurs changements."
        else:
            pass

        if 'message_user' in locals():
            send_notification(user, message_user, 'housing_search_updated')
            self.send_notification_to_parents(user, message_parent)
            self.send_notification_to_admins(message_admin, f"{instance.user.first_name} {instance.user.last_name}", instance.user.id)

        return instance

    def get_field_name(self, field_name):
        field_mapping = {
            'user.first_name': 'Prénom',
            'user.last_name': 'Nom',
            'user.phone_number': 'Numéro de téléphone',
            'town': 'Lieu de naissance',
            'user.date_of_birth': 'Date de naissance',
            'email': 'Adresse e-mail',
            'user.nationality': 'Nationalité',
            'country_code': 'Code pays',
            'country': 'Pays',
            'accommodation_type': 'Type de logement',
            'preferred_location': 'Lieu préféré',
            'move_in_date': 'Date d\'entrée',
            'stay_duration': 'Durée de séjour',
            'budget': 'Budget',
            'special_needs': 'Besoin spécial',
            'purpose_of_stay': 'Objet du séjour',
            'number_of_occupants': 'Nombre d\'occupants',
            'university_or_workplace': 'Université ou lieu de travail',
            'files': 'Fichiers'
        }
        return field_mapping.get(field_name, field_name)
    
    def send_notification_to_parents(self, user, message):
        for parent in user.student.parents.all():
            send_notification(parent.user, message, 'parent_notification')
            
    def send_notification_to_admins(self, message, student_name, student_id):
        admins = User.objects.filter(role='admin')
        for admin in admins:
            send_notification(admin, f"{message} ", 'admin_notification')


class TicketingServiceSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    phone_number = serializers.CharField(source='user.phone_number', required=False)
    place_of_birth = serializers.CharField(source='user.town', required=False)
    date_of_birth = serializers.DateField(source='user.date_of_birth', required=False)
    email = serializers.EmailField(source='user.email', required=False)
    nationality = serializers.CharField(source='user.nationality', required=False)
    country_code = serializers.CharField(source='user.country_code', required=False)
    country = serializers.CharField(source='user.country', required=False)
    files = FileSerializer(required=False)

    class Meta:
        model = TicketingService
        fields = [
            'id', 'first_name', 'last_name', 'phone_number', 'place_of_birth', 'date_of_birth',
            'email', 'nationality', 'country_code', 'country','departure_country', 'departure_city','destination_country', 'destination_city',
            'departure_date', 'return_date', 'number_of_passengers', 'travel_class',
            'preferred_airlines', 'special_requests', 'files'
        ]
    def validate(self, attrs):
        
        departure_date = attrs.get('departure_date')
        return_date = attrs.get('return_date')

        # Vérifier que la date de départ est dans le futur
        if departure_date and departure_date <= date.today():
            raise serializers.ValidationError(
                {"departure_date": ("La date de départ doit être postérieure à la date du jour.")}
            )

        # Vérifier que la date de retour est postérieure à la date de départ
        if return_date and departure_date and return_date <= departure_date:
            raise serializers.ValidationError(
                {"return_date": ("La date de retour doit être postérieure à la date de départ.")}
            )
        return attrs
        

    def create(self, validated_data):
        files_data = validated_data.pop('files', None)
        user_data = validated_data.pop('user')
        user = self.context['request'].user
       
        if user.is_anonymous:
            raise PermissionDenied("You must be logged in to create a ticketing service.")

        for attr, value in user_data.items():
            setattr(user, attr, value)
        user.save()

        ticketing_service = TicketingService.objects.create(user=user, **validated_data)

        if files_data:
            files = File.objects.create(**files_data)
            ticketing_service.files = files
            ticketing_service.save()
        message = "Vous avez créé un service de billetterie avec succès."
        send_notification(user, message, 'certificate_created')
        self.send_notification_to_parents(user,"Votre enfant a créé un nouveau service de billetterie.")
        admin_message="Un service de billetterie a été  créé."
        self.send_notification_to_admins(admin_message, f"{user.first_name} {user.last_name}", user.id)
        return ticketing_service

    def update(self, instance, validated_data):
        files_data = validated_data.pop('files', None)
        user_data = validated_data.pop('user', {})

        user = self.context['request'].user

        if instance.user != user:
            raise PermissionDenied("You cannot update this ticketing service.")

        changed_fields = {}

        if user_data:
            for attr, value in user_data.items():
                if getattr(user, attr) != value:
                    changed_fields[f"user.{attr}"] = value
                setattr(user, attr, value)
            user.save()

        if files_data:
            files_serializer = FileSerializer(instance.files, data=files_data)
            if files_serializer.is_valid():
                files_serializer.save()
                changed_fields['files'] = 'Mis à jour'

        for attr, value in validated_data.items():
            if getattr(instance, attr) != value:
                changed_fields[attr] = value
            setattr(instance, attr, value)
        instance.save()

        all_changed_fields = list(changed_fields.keys())

        if len(all_changed_fields) == 0:
            pass
        elif len(all_changed_fields) <= 3:
            field_names = [self.get_field_name(field) for field in all_changed_fields]
            message_user = f"Le service de billetterie a été mis à jour avec succès. Champ(s) mis à jour : {', '.join(field_names)}"
            message_parent = f"Votre enfant {instance.user.first_name} {instance.user.last_name} a mis à jour son service de billetterie : {', '.join(field_names)}."
            message_admin = f"Un service de billetterie a été mis à jour pour {instance.user.first_name} {instance.user.last_name}. Champ(s) mis à jour : {', '.join(field_names)} ."
        else:
            message_user = f"Le service de billetterie a été mis à jour avec succès. Vous avez modifié plus de {len(all_changed_fields)} champs."
            message_parent = f"Votre enfant {instance.user.first_name} {instance.user.last_name} a mis à jour son service de billetterie avec plusieurs changements."
            message_admin = f"Un service de billetterie a été mis à jour pour {instance.user.first_name} {instance.user.last_name} )."

        if 'message_user' in locals():
            send_notification(user, message_user, 'ticketing_service_updated')
            self.send_notification_to_parents(user, message_parent)
            self.send_notification_to_admins(message_admin, f"{instance.user.first_name} {instance.user.last_name}", instance.user.id)



        return instance
    
    def send_notification_to_parents(self, user, message):
        for parent in user.student.parents.all():
            send_notification(parent.user, message, 'parent_notification')


    def send_notification_to_admins(self, message, student_name, student_id):
            admins = User.objects.filter(role='admin')
            for admin in admins:
                send_notification(admin, f"{message}  ", 'admin_notification')
                
    def get_field_name(self, field_name):
        field_mapping = {
            'user.first_name': 'Prénom',
            'user.last_name': 'Nom',
            'user.phone_number': 'Numéro de téléphone',
            'user.town': 'Lieu de naissance',
            'user.date_of_birth': 'Date de naissance',
            'email': 'Adresse e-mail',
            'user.nationality': 'Nationalité',
            'user.country_code': 'Code pays',
            'country': 'Pays',
            'departure_country': 'Pays de départ',
            'departure_city': 'Ville de départ',
            'destination_country': 'Pays de destination',
            'destination_city': 'Ville de destination',
            'departure_date': 'Date de départ',
            'return_date': 'Date de retour',
            'number_of_passengers': 'Nombre de passagers',
            'travel_class': 'Classe de voyage',
            'preferred_airlines': 'Compagnies aériennes préférées',
            'special_requests': 'Demandes spéciales',
            'files': 'Fichiers'
        }
        return field_mapping.get(field_name, field_name)


class ReferralCreateSerializer(serializers.ModelSerializer):
    referred_by_code = serializers.CharField(write_only=True)

    class Meta:
        model = Student
        fields = ['referred_by_code']

    def create(self, validated_data):
        referred_by_code = validated_data.pop('referred_by_code', None)
        student = super().create(validated_data)

        if referred_by_code:
            try:
                referral = Referral.objects.get(code=referred_by_code)
                referral.referred_users.add(student.user)
                referral.reward_referrer(amount=50.0)
                referral.save()
            except Referral.DoesNotExist:
                pass

        return student


class ParentReferenceCodeSerializer(serializers.ModelSerializer):
    parent_reference_code = serializers.UUIDField(read_only=True)

    class Meta:
        model = Student
        fields = ['parent_reference_code']

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = ['id', 'name', 'price', 'description', 'is_popular']

class UserSubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSubscription
        fields = ['plan', 'start_date', 'end_date', 'is_active']
        read_only_fields = ['user', 'start_date']

    def create(self, validated_data):
        user = self.context['request'].user
        plan = validated_data.pop('plan')

        # Create the subscription
        user_subscription = UserSubscription.objects.create(user=user, plan=plan, **validated_data)

        # Create a payment record for the subscription
        default_payment_method = PaymentMethod.objects.filter(user=user).first()
        if default_payment_method:
            Payment.objects.create(
                user=user,
                service_name=f'Subscription to {plan.name}',
                method=default_payment_method,
                status='completed',  # or 'pending' based on your logic
                amount=plan.price
            )

        return user_subscription

# class EmailTemplateSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = EmailTemplate
#         fields = ['id', 'name', 'subject', 'content']

#     def create(self, validated_data):
#         return EmailTemplate.objects.create(**validated_data)

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
