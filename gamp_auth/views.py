from django.conf import settings
from django.contrib.auth import login
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken

from .models import User, OTP
from .serializers import OTPSendSerializer, OTPVerifySerializer, UserSerializer
from .utils import send_otp_via_sns, verify_otp_code, get_tokens_for_user

MAX_INCORRECT_ATTEMPTS = settings.MAX_INCORRECT_ATTEMPTS


@api_view(['POST'])
def generate_otp(request):
    serializer = OTPSendSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data.get('email')
        mobile_no = serializer.validated_data.get('mobile_no')
        user = None

        if email:
            user, created = User.objects.get_or_create(email=email)
        elif mobile_no:
            user, created = User.objects.get_or_create(mobile_no=mobile_no)

        if user.is_blocked:
            return Response({'error': 'User is blocked due to multiple incorrect OTP attempts'},
                            status=status.HTTP_403_FORBIDDEN)

        OTP.objects.filter(user=user, is_used=False).update(is_used=True)  # Invalidate old OTPs

        otp = OTP.objects.create(user=user)

        # Send OTP via SNS
        if mobile_no:
            response = send_otp_via_sns(mobile_no, otp.otp)
            print(f'Sending OTP {otp.otp} to mobile {mobile_no}, SNS Response: {response}')

        return Response({'message': 'OTP sent'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def verify_otp(request):
    serializer = OTPVerifySerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data.get('email')
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
            user.save()
            return Response({'error': 'Invalid OTP or expired'}, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_user_details(request):
    user = request.user
    serializer = UserSerializer(user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def verify_access_token(request):
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Decode the token to check its validity
        AccessToken(token)
        return Response({'message': 'Token is valid'}, status=status.HTTP_200_OK)
    except TokenError as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
