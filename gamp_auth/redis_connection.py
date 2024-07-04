import redis
from django.conf import settings
import logging
import time
from redis.exceptions import ConnectionError, TimeoutError

logger = logging.getLogger(__name__)


class RedisConnection(object):
    def __init__(self):
        self.connection_params = self._get_connection_params()
        self.redis = None
        self.max_retries = getattr(settings, 'REDIS_MAX_RETRIES', 3)
        self.retry_delay = getattr(settings, 'REDIS_RETRY_DELAY', 1)
        self.socket_timeout = getattr(settings, 'REDIS_SOCKET_TIMEOUT', 5)
        self.socket_connect_timeout = getattr(settings, 'REDIS_SOCKET_CONNECT_TIMEOUT', 2)
        self.health_check_interval = getattr(settings, 'REDIS_HEALTH_CHECK_INTERVAL', 30)

        self._connect()

    def _get_connection_params(self):
        connection_params = {
            'host': settings.REDIS_HOST,
            'port': settings.REDIS_PORT,
            'db': settings.REDIS_DB,
            'connection_pool': settings.REDIS_CONNECTION_POOL,
            'socket_timeout': self.socket_timeout,
            'socket_connect_timeout': self.socket_connect_timeout,
            'health_check_interval': self.health_check_interval,
        }

        if getattr(settings, 'REDIS_TLS', False):
            connection_params['ssl_cert_reqs'] = None
            connection_params['ssl'] = True

        if getattr(settings, 'REDIS_PASSWORD', None):
            connection_params['password'] = settings.REDIS_PASSWORD

        return connection_params

    def _connect(self):
        for attempt in range(self.max_retries):
            try:
                self.redis = redis.Redis(**self.connection_params)
                self.redis.ping()
                logger.info("Connected to Redis successfully")
                return
            except (ConnectionError, TimeoutError) as e:
                logger.warning(f"Redis connection attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                else:
                    logger.error("Max retries reached. Redis connection failed.")
                    raise

    def get_redis_connection(self):
        if not self.redis:
            self._connect()
        return self.redis

    def execute_with_retry(self, method, *args, **kwargs):
        for attempt in range(self.max_retries):
            try:
                return method(*args, **kwargs)
            except (ConnectionError, TimeoutError) as e:
                logger.warning(f"Redis operation failed (attempt {attempt + 1}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    self._connect()  # Try to re-establish the connection
                else:
                    logger.error("Max retries reached. Redis operation failed.")
                    raise

    def set(self, key, value, *args, **kwargs):
        return self.execute_with_retry(self.redis.set, key, value, *args, **kwargs)

    def get(self, key):
        return self.execute_with_retry(self.redis.get, key)

    def setex(self, key, time, value):
        """Set key to hold the string value and set key to timeout after a given number of seconds."""
        return self.execute_with_retry(self.redis.setex, key, time, value)

    def publish(self, channel, message):
        """Publish message to channel."""
        return self.execute_with_retry(self.redis.publish, channel, message)
