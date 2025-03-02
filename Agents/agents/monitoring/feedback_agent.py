from typing import Dict, Any, List, Optional, Tuple
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
from datetime import datetime, timedelta
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os
import asyncio
from collections import defaultdict

class FeedbackAgent(BaseAgent):
    """Agent responsible for collecting and processing feedback to improve detection capabilities."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("feedback", config)
        self.model_directory = config.get('model_directory', 'models')
        self.feedback_threshold = config.get('feedback_threshold', 100)
        self.retraining_interval = timedelta(days=config.get('retraining_interval_days', 7))
        self.last_training_time = None
        self.feature_importance_threshold = config.get('feature_importance_threshold', 0.05)
        self.feedback_weights = {
            'user_report': 1.0,
            'admin_review': 2.0,
            'automated_verification': 1.5
        }
        self.model = None
        self.scaler = None
        self.feature_columns = []

    async def initialize(self) -> None:
        """Initialize the feedback agent."""
        self.logger.info("Initializing Feedback Agent")
        os.makedirs(self.model_directory, exist_ok=True)
        await self._load_model()
        asyncio.create_task(self._schedule_model_retraining())

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process feedback data and update the model if necessary."""
        try:
            feedback_type = data.get('feedback_type', 'user_report')
            incident_id = data.get('incident_id')
            
            # Process and store feedback
            processed_feedback = await self._process_feedback(data)
            
            # Check if we need to retrain the model
            feedback_count = await self._get_recent_feedback_count()
            if feedback_count >= self.feedback_threshold:
                await self._retrain_model()
            
            # Update feature importance metrics
            if self.model is not None:
                await self._update_feature_importance()
            
            return processed_feedback

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _process_feedback(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process and validate feedback data."""
        feedback = {
            'timestamp': datetime.utcnow().isoformat(),
            'incident_id': data.get('incident_id'),
            'feedback_type': data.get('feedback_type', 'user_report'),
            'is_phishing': data.get('is_phishing', True),
            'confidence': data.get('confidence', 1.0),
            'features': data.get('features', {}),
            'metadata': {
                'source': data.get('source', 'unknown'),
                'user_id': data.get('user_id'),
                'environment': data.get('environment', 'production')
            }
        }

        # Apply feedback weights
        feedback['weighted_confidence'] = (
            feedback['confidence'] * 
            self.feedback_weights.get(feedback['feedback_type'], 1.0)
        )

        # Store feedback in database
        await db.store_feedback(feedback)

        # Notify other agents about the feedback
        await self._notify_agents(feedback)

        return feedback

    async def _load_model(self) -> None:
        """Load the latest trained model if it exists."""
        try:
            model_path = os.path.join(self.model_directory, 'feedback_model.joblib')
            scaler_path = os.path.join(self.model_directory, 'feature_scaler.joblib')
            
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.feature_columns = joblib.load(
                    os.path.join(self.model_directory, 'feature_columns.joblib')
                )
                self.last_training_time = datetime.fromtimestamp(
                    os.path.getmtime(model_path)
                )
                self.logger.info("Loaded existing feedback model")
            else:
                self.logger.info("No existing model found")

        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            self.model = None
            self.scaler = None

    async def _retrain_model(self) -> None:
        """Retrain the model with recent feedback data."""
        try:
            # Get training data
            feedback_data = await self._get_training_data()
            if not feedback_data:
                self.logger.warning("No training data available")
                return

            # Prepare features and labels
            features, labels = self._prepare_training_data(feedback_data)
            
            if len(features) < self.feedback_threshold:
                self.logger.warning("Insufficient training data")
                return

            # Train new model
            new_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            
            # Fit scaler
            new_scaler = StandardScaler()
            scaled_features = new_scaler.fit_transform(features)
            
            # Train model
            new_model.fit(scaled_features, labels)
            
            # Save new model
            self._save_model(new_model, new_scaler, features.columns)
            
            # Update instance variables
            self.model = new_model
            self.scaler = new_scaler
            self.feature_columns = features.columns
            self.last_training_time = datetime.utcnow()
            
            # Log training metrics
            await self._log_training_metrics(new_model, scaled_features, labels)

        except Exception as e:
            self.logger.error(f"Error retraining model: {str(e)}")
            raise

    def _save_model(self, model: RandomForestClassifier, scaler: StandardScaler, 
                   feature_columns: List[str]) -> None:
        """Save the trained model and associated data."""
        try:
            model_path = os.path.join(self.model_directory, 'feedback_model.joblib')
            scaler_path = os.path.join(self.model_directory, 'feature_scaler.joblib')
            columns_path = os.path.join(self.model_directory, 'feature_columns.joblib')
            
            joblib.dump(model, model_path)
            joblib.dump(scaler, scaler_path)
            joblib.dump(feature_columns, columns_path)
            
            self.logger.info("Saved updated feedback model")

        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            raise

    async def _get_training_data(self) -> List[Dict[str, Any]]:
        """Retrieve feedback data for training."""
        try:
            # Get recent feedback data
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=90)  # Last 90 days of feedback
            
            feedback_data = await db.get_feedback_data(start_date, end_date)
            
            # Filter and validate feedback data
            valid_feedback = []
            for feedback in feedback_data:
                if self._validate_feedback_data(feedback):
                    valid_feedback.append(feedback)
            
            return valid_feedback

        except Exception as e:
            self.logger.error(f"Error getting training data: {str(e)}")
            return []

    def _validate_feedback_data(self, feedback: Dict[str, Any]) -> bool:
        """Validate feedback data for training."""
        required_fields = ['features', 'is_phishing', 'confidence']
        
        if not all(field in feedback for field in required_fields):
            return False
        
        if not feedback['features']:
            return False
        
        if not isinstance(feedback['is_phishing'], bool):
            return False
        
        if not (0 <= feedback['confidence'] <= 1):
            return False
        
        return True

    def _prepare_training_data(self, feedback_data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare feedback data for model training."""
        # Extract features and labels
        feature_dict = defaultdict(list)
        labels = []
        
        for feedback in feedback_data:
            for feature, value in feedback['features'].items():
                feature_dict[feature].append(float(value))
            labels.append(int(feedback['is_phishing']))
        
        # Convert to numpy arrays
        features = np.array([feature_dict[f] for f in sorted(feature_dict.keys())]).T
        labels = np.array(labels)
        
        return features, labels

    async def _update_feature_importance(self) -> None:
        """Update feature importance metrics."""
        if self.model is None or not self.feature_columns:
            return

        try:
            importance_scores = {
                feature: score
                for feature, score in zip(self.feature_columns, self.model.feature_importances_)
                if score >= self.feature_importance_threshold
            }
            
            # Store feature importance metrics
            await db.store_feature_importance(importance_scores)
            
            # Notify other agents about important features
            await self._notify_feature_importance(importance_scores)

        except Exception as e:
            self.logger.error(f"Error updating feature importance: {str(e)}")

    async def _notify_feature_importance(self, importance_scores: Dict[str, float]) -> None:
        """Notify other agents about feature importance updates."""
        try:
            message = {
                'type': 'feature_importance_update',
                'timestamp': datetime.utcnow().isoformat(),
                'importance_scores': importance_scores
            }
            
            # Notify analysis agents
            await mq.publish('analysis.features', message)
            
            # Notify intelligence agents
            await mq.publish('intelligence.features', message)

        except Exception as e:
            self.logger.error(f"Error notifying feature importance: {str(e)}")

    async def _schedule_model_retraining(self) -> None:
        """Schedule periodic model retraining."""
        while True:
            try:
                # Check if retraining is needed
                if (self.last_training_time is None or 
                    datetime.utcnow() - self.last_training_time >= self.retraining_interval):
                    await self._retrain_model()
                
                # Wait for next check
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                self.logger.error(f"Error in retraining scheduler: {str(e)}")
                await asyncio.sleep(3600)  # Retry in an hour

    async def _get_recent_feedback_count(self) -> int:
        """Get count of recent feedback entries."""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=7)  # Last 7 days
            
            return await db.get_feedback_count(start_date, end_date)

        except Exception as e:
            self.logger.error(f"Error getting feedback count: {str(e)}")
            return 0

    async def _log_training_metrics(self, model: RandomForestClassifier, 
                                  features: np.ndarray, labels: np.ndarray) -> None:
        """Log model training metrics."""
        try:
            # Calculate basic metrics
            predictions = model.predict(features)
            accuracy = np.mean(predictions == labels)
            
            metrics = {
                'timestamp': datetime.utcnow().isoformat(),
                'accuracy': float(accuracy),
                'feature_count': len(self.feature_columns),
                'training_samples': len(labels),
                'model_version': datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            }
            
            # Store metrics
            await db.store_training_metrics(metrics)
            
            self.logger.info(f"Model training completed with accuracy: {accuracy:.4f}")

        except Exception as e:
            self.logger.error(f"Error logging training metrics: {str(e)}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Feedback Agent")
        # Save final model state if needed
        if self.model is not None:
            self._save_model(self.model, self.scaler, self.feature_columns) 