from django.conf import settings
from django.contrib.auth import login
from rest_framework import status, permissions
from rest_framework.permissions import AllowAny
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import AccessToken
import logging

from .models import User, OTP
from .serializers import OTPSendSerializer, OTPVerifySerializer, UserSerializer, UserRegistrationSerializer
from .utils import send_otp_via_sns, verify_otp_code, get_tokens_for_user, send_otp_via_email, send_blocked_email

MAX_INCORRECT_ATTEMPTS = settings.MAX_INCORRECT_ATTEMPTS

logger = logging.getLogger(__file__)


@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    data = request.data
    allowed_fields = {'email', 'mobile_no'}

    # Check for extra fields
    extra_fields = set(data.keys()) - allowed_fields
    if extra_fields:
        return Response({"error": f"No extra fields are allowed: {', '.join(extra_fields)}"},
                        status=status.HTTP_400_BAD_REQUEST)
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({'message': 'User registered successfully', 'user_id': user.id}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
def generate_otp(request):
    serializer = OTPSendSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data.get('email')
        if email:
            email = email.lower()
        mobile_no = serializer.validated_data.get('mobile_no')
        user = None

        if email:
            user, created = User.objects.get_or_create(email=email)
        elif mobile_no:
            user, created = User.objects.get_or_create(mobile_no=mobile_no)

        if user.is_blocked:
            return Response({'error': 'User is blocked due to multiple incorrect OTP attempts'},
                            status=status.HTTP_403_FORBIDDEN)

        latest_otps = OTP.objects.filter(user=user, is_used=False).order_by('-created_at')
        if latest_otps.count() >= 1:
            latest_otp = latest_otps.first()
            if latest_otp.is_valid():
                return Response({'error': 'Previous OTP is still valid'}, status=status.HTTP_400_BAD_REQUEST)

        OTP.objects.filter(user=user, is_used=False).update(is_used=True)  # Invalidate old OTPs

        otp = OTP.objects.create(user=user)

        # Send OTP via SNS
        if mobile_no:
            response = send_otp_via_sns(mobile_no, otp.otp)
            logger.info(f'Sending OTP {otp.otp} to mobile {mobile_no}, SNS Response: {response}')
        if email:
            response = send_otp_via_email(email, otp.otp)
            logger.info(f'Sending OTP {otp.otp} to email {email}, Email Response: {response}')

        return Response({'message': 'OTP sent'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
def verify_otp(request):
    serializer = OTPVerifySerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data.get('email')
        if email:
            email = email.lower()
        mobile_no = serializer.validated_data.get('mobile_no')
        otp_code = serializer.validated_data['otp']
        user = None

        if email:
            user = User.objects.filter(email=email).first()
        elif mobile_no:
            user = User.objects.filter(mobile_no=mobile_no).first()

        if user.is_blocked:
            return Response({'error': 'User is blocked due to multiple incorrect OTP attempts'},
                            status=status.HTTP_403_FORBIDDEN)

        if verify_otp_code(user, otp_code):
            login(request, user)
            tokens = get_tokens_for_user(user)
            return Response({'message': 'OTP verified', 'tokens': tokens}, status=status.HTTP_200_OK)
        else:
            user.incorrect_otp_attempts += 1
            if user.incorrect_otp_attempts >= MAX_INCORRECT_ATTEMPTS:
                user.is_blocked = True
                send_blocked_email(user.email)

            user.save()
            return Response({'error': 'Invalid OTP or expired'}, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@authentication_classes([JWTAuthentication])
def get_user_details(request):
    user = request.user
    serializer = UserSerializer(user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
# Disable authentication for this view
@authentication_classes([])
def verify_access_token(request):
    logger.debug("Entered verify_access_token view")
    auth_header = request.headers.get('Authorization')
    logger.debug(f"Authorization header: {auth_header}")

    if not auth_header or not auth_header.startswith('Bearer '):
        logger.error("Authorization header with Bearer token is required")
        return Response({'error': 'Authorization header with Bearer token is required'},
                        status=status.HTTP_400_BAD_REQUEST)

    token = auth_header.split(' ')[1]
    logger.debug(f"Extracted token: {token}")

    try:
        # Decode the token to check its validity
        access_token = AccessToken(token)
        user_id = access_token[settings.SIMPLE_JWT['USER_ID_CLAIM']]
        logger.debug(f"User ID: {user_id}")
        user = User.objects.filter(id=user_id).first()
        if not user:
            logger.error(f"User with ID {user_id} not found")
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        user_serialized_data = UserSerializer(user).data
        logger.debug("Token is valid")
        return Response({'message': 'Token is valid', 'data': user_serialized_data}, status=status.HTTP_200_OK)
    except TokenError as e:
        logger.error(f"Token error: {str(e)}")
        return Response({'error': 'Token is invalid or expired'}, status=status.HTTP_400_BAD_REQUEST)
