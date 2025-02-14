from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .api import *


router = DefaultRouter()
router.register(r'referral', ReferralViewSet, basename='referral')

urlpatterns = [
    path('register/', StudentRegistrationView.as_view(), name='student_register'),
    path('profile/', StudentProfileView.as_view(), name='student_profile'),
    path('parent_reference_code/', ParentReferenceCodeView.as_view(), name='parent-reference-code'),
    path('certificate/', CertificateView.as_view(), name='student_certificate'),
    path('certificate/delete-file/', DeleteCertificateFile.as_view(), name='delete-certificate-file'),
    path('housing/', HousingSearchView.as_view(), name='student_housing'),
    path('insurance/', InsuranceView.as_view(), name='student_insurance'),
    path('ticketing/', TicketingServiceView.as_view(), name='student_ticketing'),
    path('subscription/', SubscriptionPlanView.as_view(), name='subscription_plans'),
    path('subscribe/', UserSubscriptionView.as_view(), name='student_subscribe'),
    path('subscription-details/', UserSubscriptionDetailView.as_view(), name='student_subscription_detail'),
    path('payments/', PaymentView.as_view(), name='payments'),
    path('service-abon/', ServiceAbonAPIView.as_view(), name='service-abon'),
    path('services/files/', ServiceFilesAPIView.as_view(), name='service-abon'),
    path('', include(router.urls)),
]
