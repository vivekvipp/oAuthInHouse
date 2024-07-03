import redis
from django.conf import settings
import logging

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all logs
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


class RedisConnection(object):
    def __init__(self):
        connection_params = {}
        connection_params['host'] = settings.REDIS_HOST,
        connection_params['port'] = settings.REDIS_PORT,
        connection_params['db'] = settings.REDIS_DB
        if hasattr(settings, 'REDIS_TLS') and settings.REDIS_TLS:
            connection_params['ssl_cert_reqs'] = None
            connection_params['ssl'] = True

        if hasattr(settings, 'REDIS_PASSWORD') and settings.REDIS_PASSWORD:
            connection_params['password'] = settings.REDIS_PASSWORD

        self.connection_params = connection_params

        try:
            self.redis = redis.Redis(**self.connection_params)
            # Test connection
            self.redis.ping()
            logger.info("Connected to Redis successfully")
        except redis.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}")
            raise

    def get_redis_connection(self):
        return self.redis
