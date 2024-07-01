from .settings import DATABASES
import os

# Development settings
DATABASES['default'].update({
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': os.environ.get('DEV_DB_NAME'),
    'USER': os.environ.get('DEV_DB_USER'),
    'PASSWORD': os.environ.get('DEV_DB_PASSWORD'),
    'HOST': os.environ.get('DEV_DB_HOST'),
    'PORT': os.environ.get('DEV_DB_PORT'),
})

SECRET_KEY = os.environ.get('SECRET_KEY')

DEBUG = True
ALLOWED_HOSTS = ['*']
