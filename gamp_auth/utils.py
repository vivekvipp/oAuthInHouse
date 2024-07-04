import boto3
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from .models import OTP, OTPLog
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from .redis_connection import RedisConnection

import logging

logger = logging.getLogger(__name__)


def send_otp_via_sns(mobile_no, otp):
    # TODO: Load fixtures for getting indian numbers
    indian_prefix = "+91"
    if mobile_no.startswith("+91"):
        pass
    else:
        mobile_no = indian_prefix + mobile_no
    sns_client = boto3.client(
        'sns',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION_NAME
    )

    response = sns_client.publish(
        PhoneNumber=mobile_no,
        Message=f'Your gamp one time passcode is {otp}'
    )
    try:
        # Create an OTPLog entry based on the response
        OTPLog.objects.create(
            mobile_no=mobile_no,
            otp=otp,
            message_id=response.get('MessageId'),
            status=response['ResponseMetadata'].get('HTTPStatusCode'),
            response_metadata=response['ResponseMetadata']
        )
    except Exception as e:
        logger.error(f"Error creating OTPLog entry: {e}")
    return response


def verify_otp_code(user, otp_code):
    try:
        r = RedisConnection().get_redis_connection()
        stored_user_id = r.get(f'otp:{otp_code}')
        if stored_user_id and int(stored_user_id) == user.id:
            otp = OTP.objects.filter(user=user, otp=otp_code, is_used=False).first()
            if otp and otp.is_valid():
                otp.is_used = True
                otp.save()
                user.incorrect_otp_attempts = 0
                user.save()
                r.delete(f'otp:{otp_code}')
                return True
    except Exception as esc:
        otp = OTP.objects.filter(user=user, otp=otp_code, is_used=False).first()
        if otp and otp.is_valid():
            otp.is_used = True
            otp.save()
            user.incorrect_otp_attempts = 0
            user.save()
            return True

    return False


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }


def send_otp_via_email(email, otp):
    subject = 'Welcome to Gamp'
    context = {'otp': otp}
    from_email = settings.EMAIL_HOST_USER
    message = render_to_string('otp_template.html', context)
    email_message = EmailMessage(subject, message, to=[email], from_email=from_email)
    email_message.content_subtype = 'html'  # Set the content type to HTML
    email_message.send()


def send_blocked_email(email):
    subject = 'Account Blocked'
    context = {'REJOIN_TRAIL_URL': settings.DISCORD_URL}
    from_email = settings.EMAIL_HOST_USER
    message = render_to_string('blocked_email.html', context)
    email_message = EmailMessage(subject, message, to=[email], from_email=from_email)
    email_message.content_subtype = 'html'
    email_message.send()
