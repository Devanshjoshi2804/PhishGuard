from typing import Dict, Any
import json
import redis.asyncio as redis
import os
import asyncio
import logging

logger = logging.getLogger(__name__)

class MessageQueue:
    """Message queue utility for inter-agent communication."""
    
    def __init__(self, host='localhost', port=6379, password=None):
        self.host = host
        self.port = port
        self.password = password or os.getenv('REDIS_PASSWORD')
        self.redis_client = None

    async def connect(self):
        """Establish connection to Redis."""
        try:
            self.redis_client = redis.Redis(
                host=self.host,
                port=self.port,
                password=self.password,
                decode_responses=True
            )
            # Test the connection
            await self.redis_client.ping()
            logger.info("Successfully connected to Redis")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    async def close(self):
        """Close Redis connection."""
        if self.redis_client:
            await self.redis_client.close()
            self.redis_client = None
            logger.info("Redis connection closed")

    async def publish(self, channel: str, message: Dict[str, Any]) -> None:
        """Publish a message to a channel."""
        if not self.redis_client:
            await self.connect()
        try:
            message_str = json.dumps(message)
            await self.redis_client.publish(channel, message_str)
            logger.debug(f"Published message to {channel}")
        except Exception as e:
            logger.error(f"Failed to publish message: {e}")
            raise

    async def subscribe(self, channel: str):
        """Subscribe to a channel and yield messages."""
        if not self.redis_client:
            await self.connect()
        try:
            pubsub = self.redis_client.pubsub()
            await pubsub.subscribe(channel)
            logger.debug(f"Subscribed to {channel}")
            
            while True:
                message = await pubsub.get_message()
                if message and message['type'] == 'message':
                    try:
                        data = json.loads(message['data'])
                        yield data
                    except json.JSONDecodeError:
                        logger.error("Failed to decode message data")
                await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Subscription error: {e}")
            raise
        finally:
            await pubsub.unsubscribe(channel)

# Create a singleton instance
mq = MessageQueue() 