import boto3
from django.conf import settings
import redis
from rest_framework_simplejwt.tokens import RefreshToken
from .models import OTP


def send_otp_via_sns(mobile_no, otp):
    sns_client = boto3.client(
        'sns',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION_NAME
    )

    response = sns_client.publish(
        PhoneNumber=mobile_no,
        Message=f'Your OTP code is {otp}'
    )
    return response


def verify_otp_code(user, otp_code):
    r = redis.StrictRedis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB)
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
    return False


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }
