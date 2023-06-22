from django.urls import path, include
from Account.views import UserRegistrationVerifyView, UserRegistrationView, UserLoginView, UserProfileView, UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework_simplejwt.views import TokenVerifyView


urlpatterns = [
    
    # Access Token Create (This indicates whether our user authenticate is yes or not)
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),

    # Refresh Token Create ( Once the Access Token expires, it generates a new Access Token )  
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Verify The Token
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
     
    
    path('register/', UserRegistrationView.as_view(), name='UserRegistrationView'),
    path('register-otp-verify', UserRegistrationVerifyView.as_view(), name='UserRegistrationVerifyView'),
    path('login/', UserLoginView.as_view(), name='UserLoginView'),
    path('profile/', UserProfileView.as_view(), name='UserProfileView'),
    path('change-password/', UserChangePasswordView.as_view(), name='UserChangePasswordView'),
    path('reset-password-email-send/', SendPasswordResetEmailView.as_view(), name='SendPasswordResetEmailView'),

    # IF Link Verification
    # path('reset-password-email-verify/<uid>/<token>/', UserPasswordResetView.as_view(), name='UserPasswordResetSerializer'),

    # IF OTP Virefication
    path('reset-password-email-verify/', UserPasswordResetView.as_view(), name='UserPasswordResetSerializer'),





    # For Session Authentication Weneed Login Form, That whay it are needed.
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
]





## Surver = http://127.0.0.1:8000/api/token/

"""
{
  "username": "admin",
  "password": "admin"
  
}

When Access Token Time Out = {"refresh":"Your Refesh Token"}

"""