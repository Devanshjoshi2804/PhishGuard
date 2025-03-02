from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
from datetime import datetime, timedelta
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from collections import deque, namedtuple
import random
import json

# Define experience tuple structure
Experience = namedtuple('Experience', ['state', 'action', 'reward', 'next_state'])

class DQN(nn.Module):
    """Deep Q-Network for reinforcement learning."""
    
    def __init__(self, state_size: int, action_size: int):
        super(DQN, self).__init__()
        self.fc1 = nn.Linear(state_size, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, action_size)
        self.relu = nn.ReLU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        return self.fc3(x)

class ReinforcementLearningAgent(BaseAgent):
    """Agent responsible for optimizing phishing detection and response strategies using RL."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("reinforcement_learning", config)
        
        # RL parameters
        self.state_size = 20  # Size of state vector
        self.action_size = 5  # Number of possible actions
        self.memory_size = 10000
        self.batch_size = 64
        self.gamma = 0.99  # Discount factor
        self.epsilon = 1.0  # Exploration rate
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.learning_rate = 0.001
        self.update_frequency = 100  # How often to update target network
        self.min_experiences = 1000  # Minimum experiences before training

        # Initialize neural networks
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.policy_net = DQN(self.state_size, self.action_size).to(self.device)
        self.target_net = DQN(self.state_size, self.action_size).to(self.device)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        
        # Initialize optimizer
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=self.learning_rate)
        
        # Initialize replay memory
        self.memory = deque(maxlen=self.memory_size)
        
        # Training metrics
        self.steps = 0
        self.episodes = 0
        self.total_rewards = []
        
        # Action mapping
        self.actions = {
            0: 'block_sender',
            1: 'quarantine_message',
            2: 'notify_user',
            3: 'monitor_sender',
            4: 'no_action'
        }

    async def initialize(self) -> None:
        """Initialize the reinforcement learning agent."""
        self.logger.info("Initializing Reinforcement Learning Agent")
        await self._load_model_state()

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process current state and determine optimal action."""
        try:
            incident_id = data.get('incident_id')
            
            # Extract state from input data
            current_state = self._extract_state(data)
            
            # Convert state to tensor
            state_tensor = torch.FloatTensor(current_state).unsqueeze(0).to(self.device)
            
            # Select action using epsilon-greedy policy
            action_idx = self._select_action(state_tensor)
            action = self.actions[action_idx]
            
            # Execute action and get reward
            result = await self._execute_action(action, data)
            reward = self._calculate_reward(result)
            
            # Get next state
            next_state = self._extract_state(result)
            
            # Store experience in memory
            self.memory.append(Experience(
                current_state,
                action_idx,
                reward,
                next_state
            ))
            
            # Train the network if we have enough experiences
            if len(self.memory) >= self.min_experiences:
                await self._train()
            
            # Update target network periodically
            self.steps += 1
            if self.steps % self.update_frequency == 0:
                self.target_net.load_state_dict(self.policy_net.state_dict())
            
            # Prepare response
            response = {
                'incident_id': incident_id,
                'timestamp': datetime.utcnow().isoformat(),
                'action_taken': action,
                'confidence': float(torch.max(self.policy_net(state_tensor)).item()),
                'reward': reward,
                'metrics': {
                    'epsilon': self.epsilon,
                    'memory_size': len(self.memory),
                    'total_steps': self.steps,
                    'total_episodes': self.episodes
                }
            }
            
            # Store results
            await db.update_analysis_result(incident_id, {
                'reinforcement_learning_analysis': response
            })
            
            # Notify other agents
            await self._notify_agents(incident_id, response)
            
            return response

        except Exception as e:
            await self.handle_error(e)
            raise

    def _extract_state(self, data: Dict[str, Any]) -> List[float]:
        """Extract state vector from input data."""
        state = []
        
        try:
            # Email features (6 features)
            email_analysis = data.get('email_analysis', {})
            state.extend([
                len(email_analysis.get('suspicious_indicators', [])) / 10,  # Normalize
                email_analysis.get('authentication_score', 0.0),
                email_analysis.get('similarity_score', 0.0),
                email_analysis.get('urgency_score', 0.0),
                len(email_analysis.get('attachments', [])) / 5,  # Normalize
                len(email_analysis.get('links', [])) / 10  # Normalize
            ])
            
            # Domain features (4 features)
            domain_analysis = data.get('domain_analysis', {})
            state.extend([
                domain_analysis.get('age_score', 0.0),
                domain_analysis.get('reputation_score', 0.0),
                domain_analysis.get('similarity_score', 0.0),
                1.0 if domain_analysis.get('is_suspicious') else 0.0
            ])
            
            # Threat intelligence features (4 features)
            threat_intel = data.get('threat_intelligence', {})
            state.extend([
                threat_intel.get('risk_score', 0.0),
                len(threat_intel.get('matches', [])) / 10,  # Normalize
                len(threat_intel.get('campaigns', [])) / 5,  # Normalize
                threat_intel.get('confidence', 0.0)
            ])
            
            # Historical features (4 features)
            history = data.get('historical_data', {})
            state.extend([
                history.get('previous_incidents', 0) / 10,  # Normalize
                history.get('success_rate', 0.0),
                history.get('false_positive_rate', 0.0),
                history.get('average_response_time', 0) / 3600  # Normalize (hours)
            ])
            
            # User context features (2 features)
            user_context = data.get('user_context', {})
            state.extend([
                user_context.get('risk_level', 0.0),
                1.0 if user_context.get('is_targeted') else 0.0
            ])
            
        except Exception as e:
            self.logger.error(f"Error extracting state: {str(e)}")
            # Return zero vector if extraction fails
            return [0.0] * self.state_size
        
        # Ensure state vector has correct size
        if len(state) < self.state_size:
            state.extend([0.0] * (self.state_size - len(state)))
        elif len(state) > self.state_size:
            state = state[:self.state_size]
        
        return state

    def _select_action(self, state: torch.Tensor) -> int:
        """Select action using epsilon-greedy policy."""
        if random.random() > self.epsilon:
            with torch.no_grad():
                return self.policy_net(state).max(1)[1].item()
        else:
            return random.randrange(self.action_size)

    async def _execute_action(self, action: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute selected action and return result."""
        try:
            # Prepare action data
            action_data = {
                'incident_id': data.get('incident_id'),
                'action': action,
                'timestamp': datetime.utcnow().isoformat(),
                'context': data
            }
            
            # Execute action through appropriate agent
            if action == 'block_sender':
                await mq.publish('auto_response', {
                    **action_data,
                    'response_type': 'block'
                })
            elif action == 'quarantine_message':
                await mq.publish('auto_response', {
                    **action_data,
                    'response_type': 'quarantine'
                })
            elif action == 'notify_user':
                await mq.publish('alert', {
                    **action_data,
                    'alert_type': 'user_notification'
                })
            elif action == 'monitor_sender':
                await mq.publish('auto_response', {
                    **action_data,
                    'response_type': 'monitor'
                })
            
            # Wait for action result
            result = await self._wait_for_action_result(data.get('incident_id'))
            return result

        except Exception as e:
            self.logger.error(f"Error executing action: {str(e)}")
            return {'status': 'failed', 'error': str(e)}

    async def _wait_for_action_result(self, incident_id: str) -> Dict[str, Any]:
        """Wait for action result from other agents."""
        # This is a placeholder - implement actual waiting logic
        return await db.get_latest_action_result(incident_id)

    def _calculate_reward(self, result: Dict[str, Any]) -> float:
        """Calculate reward based on action result."""
        try:
            reward = 0.0
            
            # Base reward for successful action
            if result.get('status') == 'success':
                reward += 1.0
            elif result.get('status') == 'failed':
                reward -= 1.0
            
            # Additional rewards based on outcome
            if result.get('prevented_attack'):
                reward += 2.0
            if result.get('false_positive'):
                reward -= 2.0
            if result.get('user_feedback') == 'positive':
                reward += 0.5
            elif result.get('user_feedback') == 'negative':
                reward -= 0.5
            
            # Time-based penalty
            processing_time = result.get('processing_time', 0)
            if processing_time > 60:  # More than 60 seconds
                reward -= 0.1
            
            return reward

        except Exception as e:
            self.logger.error(f"Error calculating reward: {str(e)}")
            return 0.0

    async def _train(self) -> None:
        """Train the neural network using experience replay."""
        try:
            if len(self.memory) < self.batch_size:
                return

            # Sample random batch from memory
            batch = random.sample(self.memory, self.batch_size)
            
            # Prepare batch data
            states = torch.FloatTensor([exp.state for exp in batch]).to(self.device)
            actions = torch.LongTensor([exp.action for exp in batch]).to(self.device)
            rewards = torch.FloatTensor([exp.reward for exp in batch]).to(self.device)
            next_states = torch.FloatTensor([exp.next_state for exp in batch]).to(self.device)
            
            # Calculate Q-values
            current_q_values = self.policy_net(states).gather(1, actions.unsqueeze(1))
            next_q_values = self.target_net(next_states).max(1)[0].detach()
            expected_q_values = rewards + (self.gamma * next_q_values)
            
            # Calculate loss and update network
            loss = nn.MSELoss()(current_q_values, expected_q_values.unsqueeze(1))
            
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()
            
            # Update epsilon
            self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

        except Exception as e:
            self.logger.error(f"Error training network: {str(e)}")

    async def _load_model_state(self) -> None:
        """Load saved model state if available."""
        try:
            model_state = await db.get_model_state('reinforcement_learning')
            if model_state:
                self.policy_net.load_state_dict(torch.load(model_state['policy_net']))
                self.target_net.load_state_dict(torch.load(model_state['target_net']))
                self.optimizer.load_state_dict(torch.load(model_state['optimizer']))
                self.epsilon = model_state.get('epsilon', self.epsilon)
                self.steps = model_state.get('steps', 0)
                self.episodes = model_state.get('episodes', 0)
                self.logger.info("Loaded saved model state")
        except Exception as e:
            self.logger.error(f"Error loading model state: {str(e)}")

    async def _save_model_state(self) -> None:
        """Save current model state."""
        try:
            model_state = {
                'policy_net': self.policy_net.state_dict(),
                'target_net': self.target_net.state_dict(),
                'optimizer': self.optimizer.state_dict(),
                'epsilon': self.epsilon,
                'steps': self.steps,
                'episodes': self.episodes,
                'timestamp': datetime.utcnow().isoformat()
            }
            await db.save_model_state('reinforcement_learning', model_state)
        except Exception as e:
            self.logger.error(f"Error saving model state: {str(e)}")

    async def _notify_agents(self, incident_id: str, results: Dict[str, Any]) -> None:
        """Notify other agents about RL decisions."""
        try:
            # Notify the Phishing Score Agent
            await mq.publish('score_aggregation', {
                'incident_id': incident_id,
                'reinforcement_learning_analysis': results
            })

            # Notify Logging Agent
            await mq.publish('logging', {
                'incident_id': incident_id,
                'rl_decision_log': {
                    'timestamp': datetime.utcnow().isoformat(),
                    'action': results['action_taken'],
                    'confidence': results['confidence'],
                    'metrics': results['metrics']
                }
            })

        except Exception as e:
            self.logger.error(f"Error notifying agents: {str(e)}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Reinforcement Learning Agent")
        await self._save_model_state() 