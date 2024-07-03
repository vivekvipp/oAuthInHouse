import redis
from django.conf import settings


class RedisConnection(object):

    def __init__(self):
        if settings.REDIS_PASSWORD:
            self.redis = redis.StrictRedis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                password=settings.REDIS_PASSWORD
            )
        else:
            self.redis = redis.StrictRedis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB
            )

    def get_redis_connection(self):
        return self.redis
