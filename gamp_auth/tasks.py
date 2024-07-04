import logging
from celery import shared_task
from django.db.models import Q
from .models import OTP, User
from .redis_connection import RedisConnection

logger = logging.getLogger(__name__)


@shared_task
def mark_expired_otps_inactive():
    redis_conn = RedisConnection()

    try:
        r = redis_conn.get_redis_connection()
        otp_keys = r.keys('otp:*')

        for key in otp_keys:
            process_otp_key(r, key)
    except Exception as e:
        logger.error(f"Error in mark_expired_otps_inactive task: {e}", exc_info=True)


def process_otp_key(redis_client, key):
    try:
        otp_code = key.decode('utf-8').split(':')[1]
        stored_user_id = get_stored_user_id(redis_client, key)

        if not stored_user_id:
            logger.warning(f"No user ID found for OTP: {otp_code}")
            return

        user = User.objects.filter(id=stored_user_id).first()
        if not user:
            logger.warning(f"User with ID {stored_user_id} not found in the database")
            return

        otp = OTP.objects.filter(Q(otp=otp_code) & Q(user=user) & Q(is_used=False)).first()
        if otp:
            otp.is_used = True
            otp.save()
            redis_client.delete(key)
            logger.info(f"Marked OTP {otp_code} as used for user {user.id}")
        else:
            logger.info(f"No active OTP found for user {user.id} with code {otp_code}")

    except Exception as e:
        logger.error(f"Error processing OTP key {key}: {e}", exc_info=True)


def get_stored_user_id(redis_client, key):
    stored_user_id = redis_client.get(key)
    if isinstance(stored_user_id, bytes):
        return stored_user_id.decode('utf-8')
    elif isinstance(stored_user_id, str):
        return int(stored_user_id)
    return None

