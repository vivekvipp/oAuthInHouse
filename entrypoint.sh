#!/bin/sh

set -e

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

# Start the server
exec "$@"