#!/bin/sh

set -e
#

# Wait for the PostgreSQL database to be ready
if [ "$DATABASE" = "postgres" ]
then
    echo "Waiting for postgres..."

    while ! nc -z $SQL_HOST $SQL_PORT; do
      sleep 0.1
    done

    echo "PostgreSQL started"
fi

python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Start Celery worker
celery -A gamp_gateway worker --loglevel=info &

# Start Celery beat
celery -A gamp_gateway beat --loglevel=info &

# Start the server
exec gunicorn gamp_gateway.wsgi:application --bind 0.0.0.0:8000 --workers 3 --threads 2 --timeout 60 --log-level=info "$@"