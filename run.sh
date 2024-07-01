# Build the images
docker build -t gamp-gateway-web -f Dockerfile .
docker build -t gamp-gateway-celery -f Dockerfile.celery .

# Run the containers
docker run -d --name gamp-gateway-web -p 8000:8000 --env-file .env gamp-gateway-web gunicorn gamp_gateway.wsgi:application --bind 0.0.0.0:8000 --workers 3 --threads 2 --timeout 60 --log-level=info
docker run -d --name gamp-gateway-celery-worker --env-file .env gamp-gateway-celery celery -A gamp_gateway worker --loglevel=info
docker run -d --name gamp-gateway-celery-beat --env-file .env gamp-gateway-celery celery -A gamp_gateway beat --loglevel=info