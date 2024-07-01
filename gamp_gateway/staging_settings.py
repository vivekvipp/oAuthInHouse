
from .settings import DATABASES
import os


# Production settings
DATABASES['default'].update({
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': os.environ.get('STAGING_DB_NAME'),
    'USER': os.environ.get('STAGING_DB_USER'),
    'PASSWORD': os.environ.get('STAGING_DB_PASSWORD'),
    'HOST': os.environ.get('STAGING_DB_HOST'),
    'PORT': os.environ.get('PROD_DB_PORT', 5432),
})
SECRET_KEY = os.environ.get('SECRET_KEY')

DEBUG = False
ALLOWED_HOSTS = ['*']
