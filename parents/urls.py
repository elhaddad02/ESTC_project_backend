from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .api import *


router = DefaultRouter()



urlpatterns = [
    path('register/', ParentRegistrationView.as_view(), name='parent_register'),
    path('profile/', ParentProfileView.as_view(), name='parent_profile'),
    path('certficate-status/', ParentIrrevocablePaymentCertificateView.as_view(), name='parent-housing-status'),
    path('parent/child/', ParentChildProfileView.as_view(), name='parent-child-profile'),
    path('housing-status/', ParentHousingStatusView.as_view(), name='parent-housing-status'),
    path('ticketing-status/', ParentTicketingStatusView.as_view(), name='parent-ticketing-status'),
    path('insurance-status/', ParentInsuranceStatusView.as_view(), name='parent-insurance-status'),
    path('payment-history/', ParentPaymentHistoryView.as_view(), name='parent-payment-history'),
    path('service_abo/',ServiceAbonAPIViewParent.as_view(), name='service'),
    path('services/files/', ParentChildServiceFilesAPIView.as_view(), name='parent-services-files'),

    path('', include(router.urls)),
]