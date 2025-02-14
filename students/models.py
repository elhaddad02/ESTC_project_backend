from django.db import models
from authentication.models import User, Student
import string
import random
from decimal import Decimal
from django.core.validators import RegexValidator, EmailValidator

# Validators
phone_number_validator = RegexValidator(regex=r'^\d{9,15}$', message="Phone number must be between 9 and 15 digits.")
email_validator = EmailValidator(message="Enter a valid email address.")

class Guardian(models.Model):

    student = models.OneToOneField(Student, on_delete=models.CASCADE, related_name='guardian')
    father_name = models.CharField(max_length=100, blank=True, null=True)
    mother_name = models.CharField(max_length=100, blank=True, null=True)
    father_email = models.EmailField(max_length=255, blank=True, null=True, validators=[email_validator])
    mother_email = models.EmailField(max_length=255, blank=True, null=True, validators=[email_validator])
    father_country_code = models.CharField(max_length=10, blank=True, null=True)
    father_phone_number = models.CharField(max_length=15, blank=True, null=True, validators=[phone_number_validator], help_text="Enter father's phone number without country code")
    mother_country_code = models.CharField(max_length=10, blank=True, null=True)
    mother_phone_number = models.CharField(max_length=15, blank=True, null=True, validators=[phone_number_validator], help_text="Enter mother's phone number without country code")

    def __str__(self):
        return f"{self.father_name} & {self.mother_name}'s Guardian Info"

class Program(models.Model):
    student = models.OneToOneField(Student, on_delete=models.CASCADE, related_name='program')
    last_degree_obtained = models.CharField(max_length=255, blank=True, null=True)
    destination_city = models.CharField(max_length=100, blank=True, null=True)
    destination_country = models.CharField(max_length=100, blank=True, null=True)
    desired_sector = models.CharField(max_length=100, blank=True, null=True)
    university_institution = models.CharField(max_length=255, blank=True, null=True)
    academic_year = models.CharField(max_length=20, blank=True, null=True)
    accepted_program = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.student.user.first_name}'s Program"

class File(models.Model):
    preliminary_acceptance = models.FileField(upload_to='documents/', blank=True, null=True)
    payment_proof = models.FileField(upload_to='documents/', blank=True, null=True)
    passport_copy = models.FileField(upload_to='documents/', blank=True, null=True)
    additional_pdf = models.FileField(upload_to='documents/', blank=True, null=True)

    def __str__(self):
        return "Files"

    def get_file_urls(self):
        return {
            "preliminary_acceptance": self.preliminary_acceptance.url if self.preliminary_acceptance else None,
            "payment_proof": self.payment_proof.url if self.payment_proof else None,
            "passport_copy": self.passport_copy.url if self.passport_copy else None,
            "additional_pdf": self.additional_pdf.url if self.additional_pdf else None,
        }

class IrrevocablePaymentCertificate(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='payment_certificates')
    files = models.ForeignKey(File, on_delete=models.CASCADE, related_name='certificates', null=True, blank=True)

    def __str__(self):
        return f"Certificate for {self.user.email}"

class HousingSearch(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='housing_searches')
    accommodation_type = models.CharField(max_length=50)
    preferred_location = models.CharField(max_length=100)
    move_in_date = models.DateField()
    stay_duration = models.IntegerField()
    budget = models.DecimalField(max_digits=10, decimal_places=2)
    special_needs = models.TextField(blank=True)
    purpose_of_stay = models.CharField(max_length=255, blank=True, null=True)
    number_of_occupants = models.IntegerField(blank=True, null=True)
    university_or_workplace = models.CharField(max_length=255, blank=True, null=True)
    files = models.ForeignKey(File, on_delete=models.CASCADE, related_name='housing_searches', blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    rental_contract = models.FileField(upload_to='rental_contracts/', blank=True, null=True)
    renewal_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return f"Housing Search for {self.user.email}"

class PaymentMethod(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Ensure this field exists and is required
    type=models.CharField(max_length=20, blank=True, null=True)
    carte_card_number = models.CharField(max_length=20, blank=True, null=True)
    carte_expiration_date = models.CharField(max_length=5, blank=True, null=True)
    carte_cvv = models.CharField(max_length=10, blank=True, null=True)
    virement_banque_nom=models.CharField(max_length=20, blank=True, null=True)
    virement_iban=models.CharField(max_length=20, blank=True, null=True)
    virement_bic_swift=models.CharField(max_length=20, blank=True, null=True)
    virement_code_bancaire=models.CharField(max_length=20, blank=True, null=True)
    def __str__(self):
        return f"Payment Method for {self.user.email}"

class Insurance(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='insurance')
    start_date = models.DateField()
    insurance_duration = models.IntegerField()  
    insurance_type = models.CharField(max_length=100)  
    beneficiaries = models.TextField()  
    insured_amount = models.DecimalField(max_digits=10, decimal_places=2)  
    files = models.OneToOneField(File, on_delete=models.SET_NULL, null=True, blank=True)
    payment_method = models.OneToOneField(PaymentMethod, on_delete=models.SET_NULL, null=True, blank=True)
    
    def __str__(self):
        return f"{self.user.email} - {self.insurance_type}"

class TicketingService(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ticketing_services')
    departure_city = models.CharField(max_length=100)
    departure_country = models.CharField(max_length=100 , null=True)
    destination_country = models.CharField(max_length=100, null=True)
    destination_city = models.CharField(max_length=100)
    departure_date = models.DateField()
    return_date = models.DateField()
    number_of_passengers = models.IntegerField()
    travel_class = models.CharField(max_length=50)
    preferred_airlines = models.CharField(max_length=100, blank=True)
    special_requests = models.TextField(blank=True)
    files = models.ForeignKey(File, on_delete=models.CASCADE, related_name='ticketing', blank=True, null=True)

    class Meta:
        verbose_name = "Ticketing Service"
        verbose_name_plural = "Ticketing Services"

class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    service_name = models.CharField(max_length=255)
    date = models.DateField(auto_now_add=True)
    method = models.ForeignKey(PaymentMethod, on_delete=models.CASCADE, related_name='payments')
    status = models.CharField(max_length=10)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    is_history = models.BooleanField(default=False)

    def __str__(self):
        return f"Payment of {self.amount} for {self.service_name} on {self.date} - {self.status}"

class Referral(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='referral')
    code = models.CharField(max_length=10, unique=True)
    credit = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    referred_users = models.ManyToManyField(User, related_name='referred_by', blank=True)

    def __str__(self):
        return f"Referral {self.code} for {self.user.username}"

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = self.generate_unique_code()
        super().save(*args, **kwargs)

    def generate_unique_code(self):
        length = 6
        letters = string.ascii_uppercase + string.digits
        while True:
            code = ''.join(random.choice(letters) for _ in range(length))
            if not Referral.objects.filter(code=code).exists():
                break
        return code

    def reward_referrer(self, amount):
        self.credit += Decimal(amount)
        self.save()

class SubscriptionPlan(models.Model):
    PLAN_CHOICES = [
        ('standard', 'Plan Standard'),
        ('pro', 'Forfait Pro'),
        ('unlimited', 'Forfait illimité')
    ]

    name = models.CharField(max_length=100, choices=PLAN_CHOICES)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField()
    is_popular = models.BooleanField(default=False)

    def __str__(self):
        return self.get_name_display()

class UserSubscription(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='subscription')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.SET_NULL, null=True, blank=True)
    start_date = models.DateField(auto_now_add=True)
    end_date = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} - {self.plan.get_name_display()}"
