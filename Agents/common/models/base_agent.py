from abc import ABC, abstractmethod
import logging
from typing import Any, Dict, Optional
import asyncio
import json
import traceback

class BaseAgent(ABC):
    """Base class for all agents in the system."""
    
    def __init__(self, agent_id: str, config: Dict[str, Any]):
        """Initialize the base agent."""
        self.agent_id = agent_id
        self.config = config
        self.logger = logging.getLogger(f"agent.{agent_id}")
        self.logger.setLevel(logging.INFO)
        self._running = False
        self._initialized = False

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the agent with necessary setup."""
        pass

    @abstractmethod
    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming data and return results."""
        raise NotImplementedError("Process method must be implemented by child class")

    async def start(self) -> None:
        """Start the agent's processing loop."""
        if self._running:
            return

        if not self._initialized:
            await self.initialize()
            self._initialized = True

        self._running = True
        self.logger.info(f"Agent {self.agent_id} started")

    async def stop(self) -> None:
        """Stop the agent's processing loop."""
        self._running = False
        self.logger.info(f"Agent {self.agent_id} stopped")

    async def handle_error(self, error: Exception) -> None:
        """Handle errors that occur during processing."""
        self.logger.error(f"Error in {self.agent_id}: {str(error)}")
        self.logger.error(traceback.format_exc())
        # Additional error handling logic can be added here

    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the agent."""
        return {
            "agent_id": self.agent_id,
            "running": self._running,
            "initialized": self._initialized
        }

    async def send_message(self, target_agent: str, message: Dict[str, Any]) -> None:
        """Send a message to another agent."""
        # Implementation will depend on the message queue system
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        pass 