from celery import shared_task
import redis
from django.conf import settings
from .models import OTP


@shared_task
def mark_expired_otps_inactive():
    r = redis.StrictRedis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB)
    otp_keys = r.keys('otp:*')

    for key in otp_keys:
        otp_code = key.decode('utf-8').split(':')[1]
        stored_user_id = r.get(key)

        if not stored_user_id:
            otp = OTP.objects.filter(otp=otp_code, is_used=False).first()
            if otp:
                otp.is_used = True
                otp.save()
                r.delete(key)