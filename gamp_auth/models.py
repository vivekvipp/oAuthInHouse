from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import RegexValidator, validate_email
from django.db import models
from django.utils import timezone
import random
from redis_connection import RedisConnection
from django.conf import settings


class UserManager(BaseUserManager):
    def create_user(self, **extra_fields):
        email = extra_fields.get('email')
        mobile_no = extra_fields.get('mobile_no')

        if not email and not mobile_no:
            raise ValueError('Either email or mobile number must be set')

        user = self.model(**extra_fields)

        if email:
            user.email = self.normalize_email(email)

        if not user.username:
            user.username = self.create_username()

        user.save(using=self._db)
        return user

    def create_superuser(self, email=None, mobile_no=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)

        return self.create_user(email=email, mobile_no=mobile_no, **extra_fields)

    @staticmethod
    def create_username():
        while True:
            username = f'user{random.randint(1000, 9999)}'
            if not User.objects.filter(username=username).exists():
                return username


class User(AbstractBaseUser):
    email = models.EmailField(unique=True, null=True, blank=True, validators=[validate_email])
    mobile_no = models.CharField(
        max_length=15,
        unique=True,
        null=True,
        blank=True,
        validators=[RegexValidator(
            regex=r'^\+91\d{10}$',
            message="Phone number must be entered in the format: '+919999999999'. Up to 10 digits allowed."
        )]
    )
    username = models.CharField(max_length=150, unique=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    incorrect_otp_attempts = models.IntegerField(default=0)
    is_blocked = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.username


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.otp:
            self.otp = f'{random.randint(100000, 999999)}'
        super().save(*args, **kwargs)
        self.set_otp_in_redis()

    def set_otp_in_redis(self):
        r = RedisConnection().get_redis_connection()
        r.setex(f'otp:{self.otp}', 120, self.user.id)
        r.publish(settings.REDIS_OTP_CHANNEL, self.otp)

    def is_valid(self):
        return not self.is_used and (timezone.now() - self.created_at).seconds < 120
