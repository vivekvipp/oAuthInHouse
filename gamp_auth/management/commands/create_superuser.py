from django.conf import settings
from django.core.management.base import BaseCommand
from gamp_auth.models import User
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Create a superuser'

    def handle(self, *args, **kwargs):
        email = settings.ADMIN_USER_EMAIL
        mobile_no = settings.ADMIN_USER_MOBILE
        password = settings.ADMIN_USER_PASSWORD
        logger.info(f'Creating superuser with email: {email}, mobile number: {mobile_no}, password: {password}')
        if User.objects.filter(email=email).exists():
            logger.info(f'Superuser with email: {email} already exists')
            # Update user superuser status and staff, unblock user
            user = User.objects.get(email=email)
            user.email = email
            user.mobile_no = mobile_no
            user.is_staff = True
            user.is_superuser = True
            user.incorrect_otp_attempts = 0
            user.is_blocked = False
            user.is_active = True
            user.set_password(password)
            user.save()
        else:
            user = User(
                email=email,
                mobile_no=mobile_no,
                is_staff=True,
                is_superuser=True,
                is_blocked=False,
                incorrect_otp_attempts=0,
                is_active=True
            )
            user.set_password(password)
            user.save()
        logger.info(f'Superuser created with email: {email}, mobile number: {mobile_no}')
