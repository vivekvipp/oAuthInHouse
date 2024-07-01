# Use the official Python image as the base image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /code

# Install system dependencies
RUN apt-get update && apt-get install -y \
    netcat \
    postgresql-client \
    build-essential \
    libpq-dev \
    && apt-get clean

COPY requirements.txt /code/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . /code/

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]