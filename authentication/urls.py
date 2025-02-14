from django.conf.urls.static import static
from django.urls import path

from .api import *

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/', VerifyEmail.as_view(), name='email-verify'),
    path('resend-verification/', ResendVerification.as_view(), name='resend-verification'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('password-reset-request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('set-language/', set_language, name='set_language'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
