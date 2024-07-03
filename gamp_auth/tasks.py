from celery import shared_task
from .models import OTP, User
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

            if isinstance(stored_user_id, bytes):
                stored_user_id = stored_user_id.decode('utf-8')
            elif isinstance(stored_user_id, str):
                stored_user_id = int(stored_user_id)

            if not stored_user_id:
                user_obj = User.objects.filter(id=stored_user_id)
                if user_obj.count() > 1:
                    user_first = user_obj.first()
                    otp = OTP.objects.filter(otp=otp_code, user=user_first, is_used=False).first()
                    if otp:
                        otp.is_used = True
                        otp.save()
                        r.delete(key)
                logger.warn(f"User with ID {stored_user_id} not found in the database")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")