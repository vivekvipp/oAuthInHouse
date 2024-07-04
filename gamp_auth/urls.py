from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import generate_otp, verify_otp, get_user_details, verify_access_token, register_user, unblock_users

urlpatterns = [
    path('generate-otp/', generate_otp, name='generate_otp'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('user-details/', get_user_details, name='user_details'),
    path('verify-token/', verify_access_token, name='verify_token'),
    path('register/', register_user, name='register_user'),
    path('unblock-users/', unblock_users, name='unblock_users'),
]