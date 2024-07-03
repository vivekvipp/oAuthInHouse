from celery import shared_task
from .models import OTP
from .redis_connection import RedisConnection

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all logs
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


@shared_task
def mark_expired_otps_inactive():
    try:
        r = RedisConnection().get_redis_connection()
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
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")