# Gamp Auth Gateway

Gamp Auth Gateway is a Django-based authentication gateway designed to provide secure, scalable authentication services for your applications. This project integrates Celery for handling background tasks, utilizes PostgreSQL for reliable database management, and leverages Redis for caching and task queuing. JWT-based authentication ensures robust security for user sessions.

## Prerequisites

Make sure you have the following installed:

- Docker
- Python >= 3.5

## Project Structure
```
.
├── Dockerfile
├── Dockerfile.celery
├── entrypoint.sh
├── docker-compose.yml
├── requirements.txt
├── .env
├── gamp_gateway
│   ├── init.py
│   ├── asgi.py
│   ├── wsgi.py
│   ├── celery.py
│   ├── settings.py
├── gamp_auth
│   ├── init.py
│   ├── models.py
│   ├── serializers.py
│   ├── tasks.py
│   ├── urls.py
│   ├── utils.py
│   └── views.py
└── manage.py
```

## Setup Instructions

### Step 1: Create Environment Variables

Create a `.env` file in the root of your project directory and add the following environment variables:
```
SECRET_KEY=your-secret-key
POSTGRES_DB=your_db_name
POSTGRES_USER=your_db_user
POSTGRES_PASSWORD=your_db_password
SQL_HOST=db
SQL_PORT=5432
REDIS_CACHE_URL=redis://redis:6379/1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION_NAME=your_region
```

### Step 2: Run Locally
To run the project locally without Docker, follow these steps:

#### 1. Create a Virtual Environment

* Create and activate a virtual environment to isolate your dependencies.

```shell
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

#### 2. Install Dependencies

Install the required dependencies using pip.

```shell
pip install -r requirements.txt
```

#### 3. Set Up PostgreSQL Database

```shell
CREATE DATABASE your_db_name;
CREATE USER your_db_user WITH PASSWORD 'your_db_password';
ALTER ROLE your_db_user SET client_encoding TO 'utf8';
ALTER ROLE your_db_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE your_db_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE your_db_name TO your_db_user;
```

#### 4. Run Migrations

Apply the database migrations to set up the database schema.

```shell
python manage.py migrate
```

#### 5. Start Redis

Make sure Redis is installed and running on your local machine. You can start Redis using the following command:

```shell
redis-server
```
#### 6. Run the Development Server

Start the Django development server.

```shell
python manage.py runserver
```

#### 7. Start Celery Worker

In a new terminal window (while the virtual environment is still activated), start the Celery worker.

```shell
celery -A gamp worker --loglevel=info
```


### API Endpoints

    • Generate OTP: POST /auth/generate-otp/
	• Verify OTP: POST /auth/verify-otp/
	• Refresh Token: POST /auth/token/refresh/
	• Get User Details: GET /auth/user-details/
	• Verify Access Token: POST /auth/verify-token/
