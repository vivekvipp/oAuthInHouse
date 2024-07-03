import redis
from django.conf import settings


class RedisConnection(object):
    def __init__(self):
        connection_params = {
            'host': settings.REDIS_HOST,
            'port': settings.REDIS_PORT,
            'db': settings.REDIS_DB
        }

        if hasattr(settings, 'REDIS_PASSWORD') and settings.REDIS_PASSWORD:
            connection_params['password'] = settings.REDIS_PASSWORD

        self.redis = redis.Redis(connection_pool=redis.ConnectionPool(**connection_params))

    def get_redis_connection(self):
        return self.redis
