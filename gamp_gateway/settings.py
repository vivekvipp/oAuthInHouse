"""
Django settings for gamp_gateway project.

Generated by 'django-admin startproject' using Django 4.2.13.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""
from decouple import config
from pathlib import Path
from datetime import timedelta
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='gamp_auth')
ENVIRONMENT = os.environ.get('DJANGO_ENVIRONMENT', 'local')

DEBUG_FLAG = config('DEBUG', default=True)
if DEBUG_FLAG == 'FALSE':
    DEBUG = False
else:
    DEBUG = True

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='*').split(',')

AUTH_USER_MODEL = 'gamp_auth.User'

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'gamp_auth'
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTStatelessUserAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'gamp_auth.middleware.LogRequestsMiddleware',
]

ROOT_URLCONF = 'gamp_gateway.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'gamp_gateway.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://localhost:6379/0')
CELERY_BEAT_SCHEDULE_TIME = config('CELERY_BEAT_SCHEDULE_TIME', default=120.0, cast=float)
CELERY_TIMEZONE = config('CELERY_TIMEZONE', default='UTC')

CELERY_BEAT_SCHEDULE = {
    'mark_otp_inactive': {
        'task': 'gamp_auth.tasks.mark_expired_otps_inactive',
        'schedule': CELERY_BEAT_SCHEDULE_TIME,  # Run every 2 minutes
    },
}
# Redis settings for Pub/Sub
REDIS_HOST = config('REDIS_HOST', default=os.environ.get('REDIS_HOST'))
REDIS_PORT = config('REDIS_PORT', default=os.environ.get('REDIS_PORT'), cast=int)
REDIS_DB = config('REDIS_DB', default=os.environ.get('REDIS_DB'), cast=int)
REDIS_OTP_CHANNEL = config('REDIS_OTP_CHANNEL', default=os.environ.get('REDIS_OTP_CHANNEL'))
REDIS_PASSWORD = config('REDIS_PASSWORD', default=os.environ.get('REDIS_PASSWORD'))


# Redis settings for caching
def _create_redis_cache_url():
    if REDIS_PASSWORD:
        return f'redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}'
    else:
        return f'redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}'


CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": _create_redis_cache_url(),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    }
}

MAX_INCORRECT_ATTEMPTS = config('MAX_INCORRECT_ATTEMPTS', 4)

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# SNS RELATED Settings

AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID', default=os.environ.get('AWS_ACCESS_KEY_ID'))
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY', default=os.environ.get('AWS_SECRET_ACCESS_KEY'))
AWS_REGION_NAME = config('AWS_REGION_NAME', 'ap-south-1')

if ENVIRONMENT == 'production':
    from .production_settings import *
elif ENVIRONMENT == 'development':
    from .development_settings import *
elif ENVIRONMENT == 'staging':
    from .staging_settings import *
