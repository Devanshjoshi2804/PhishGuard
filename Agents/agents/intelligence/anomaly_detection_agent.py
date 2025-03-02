from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
import numpy as np
from datetime import datetime, timedelta
import json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
from collections import defaultdict

class AnomalyDetectionAgent(BaseAgent):
    """Agent responsible for detecting anomalies in phishing patterns and behaviors."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("anomaly_detection", config)
        self.models = {}
        self.scalers = {}
        self.training_window = timedelta(days=30)
        self.min_samples = 50
        self.contamination = 0.1  # Expected proportion of anomalies
        self.feature_sets = {
            'email': [
                'header_anomaly_count',
                'authentication_score',
                'link_count',
                'unique_domains',
                'text_similarity',
                'urgency_score'
            ],
            'domain': [
                'age_days',
                'ssl_validity_days',
                'dns_record_count',
                'reputation_score',
                'similarity_score'
            ],
            'behavior': [
                'request_frequency',
                'geographic_dispersion',
                'time_pattern_score',
                'target_diversity',
                'technique_complexity'
            ]
        }

    async def initialize(self) -> None:
        """Initialize the anomaly detection agent."""
        self.logger.info("Initializing Anomaly Detection Agent")
        await self._load_historical_data()
        await self._train_models()

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process data for anomaly detection."""
        try:
            incident_id = data.get('incident_id')
            
            # Extract features from various analysis results
            features = await self._extract_features(data)
            
            # Detect anomalies in different aspects
            analysis_results = {
                'incident_id': incident_id,
                'timestamp': datetime.utcnow().isoformat(),
                'anomalies': {},
                'risk_factors': [],
                'confidence_scores': {}
            }

            # Process each feature set
            for feature_set, feature_data in features.items():
                if feature_data and feature_set in self.models:
                    anomaly_results = await self._detect_anomalies(
                        feature_set,
                        feature_data
                    )
                    analysis_results['anomalies'][feature_set] = anomaly_results

            # Calculate overall risk assessment
            risk_assessment = self._calculate_risk_assessment(analysis_results)
            analysis_results.update(risk_assessment)

            # Store results
            await db.update_analysis_result(incident_id, {
                'anomaly_detection_analysis': analysis_results
            })

            # Notify other agents
            await self._notify_agents(incident_id, analysis_results)

            return analysis_results

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _load_historical_data(self) -> None:
        """Load historical data for model training."""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - self.training_window

            # Load historical analysis results
            historical_data = await db.get_historical_analysis(
                start_date.isoformat(),
                end_date.isoformat()
            )

            # Process and store features for each type
            self.historical_features = {
                feature_set: [] for feature_set in self.feature_sets
            }

            for record in historical_data:
                features = await self._extract_features(record)
                for feature_set, feature_data in features.items():
                    if feature_data:
                        self.historical_features[feature_set].append(feature_data)

        except Exception as e:
            self.logger.error(f"Error loading historical data: {str(e)}")
            raise

    async def _train_models(self) -> None:
        """Train anomaly detection models for each feature set."""
        try:
            for feature_set, features in self.historical_features.items():
                if len(features) >= self.min_samples:
                    # Convert features to numpy array
                    feature_array = np.array(features)
                    
                    # Scale features
                    scaler = StandardScaler()
                    scaled_features = scaler.fit_transform(feature_array)
                    
                    # Train isolation forest
                    model = IsolationForest(
                        contamination=self.contamination,
                        random_state=42
                    )
                    model.fit(scaled_features)
                    
                    # Store models and scalers
                    self.models[feature_set] = model
                    self.scalers[feature_set] = scaler
                    
                    self.logger.info(f"Trained model for {feature_set} with {len(features)} samples")

        except Exception as e:
            self.logger.error(f"Error training models: {str(e)}")
            raise

    async def _extract_features(self, data: Dict[str, Any]) -> Dict[str, List[float]]:
        """Extract features from analysis results."""
        features = {}
        
        try:
            # Extract email features
            if 'email_analysis' in data:
                email_features = self._extract_email_features(data['email_analysis'])
                if all(v is not None for v in email_features):
                    features['email'] = email_features

            # Extract domain features
            if 'domain_analysis' in data:
                domain_features = self._extract_domain_features(data['domain_analysis'])
                if all(v is not None for v in domain_features):
                    features['domain'] = domain_features

            # Extract behavior features
            behavior_features = self._extract_behavior_features(data)
            if all(v is not None for v in behavior_features):
                features['behavior'] = behavior_features

            return features

        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
            return {}

    def _extract_email_features(self, email_analysis: Dict[str, Any]) -> List[float]:
        """Extract features from email analysis."""
        try:
            features = [
                len(email_analysis.get('suspicious_indicators', [])),  # header_anomaly_count
                self._calculate_authentication_score(email_analysis),  # authentication_score
                email_analysis.get('link_count', 0),                  # link_count
                len(email_analysis.get('unique_domains', [])),        # unique_domains
                email_analysis.get('text_similarity', 0.0),           # text_similarity
                email_analysis.get('urgency_score', 0.0)             # urgency_score
            ]
            return features
        except Exception:
            return [0.0] * len(self.feature_sets['email'])

    def _extract_domain_features(self, domain_analysis: Dict[str, Any]) -> List[float]:
        """Extract features from domain analysis."""
        try:
            features = [
                self._calculate_domain_age(domain_analysis),          # age_days
                self._calculate_ssl_validity(domain_analysis),        # ssl_validity_days
                len(domain_analysis.get('dns_records', [])),         # dns_record_count
                domain_analysis.get('reputation_score', 0.0),        # reputation_score
                domain_analysis.get('similarity_score', 0.0)         # similarity_score
            ]
            return features
        except Exception:
            return [0.0] * len(self.feature_sets['domain'])

    def _extract_behavior_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract behavior-related features."""
        try:
            features = [
                self._calculate_request_frequency(data),              # request_frequency
                self._calculate_geographic_dispersion(data),          # geographic_dispersion
                self._calculate_time_pattern_score(data),             # time_pattern_score
                self._calculate_target_diversity(data),               # target_diversity
                self._calculate_technique_complexity(data)            # technique_complexity
            ]
            return features
        except Exception:
            return [0.0] * len(self.feature_sets['behavior'])

    def _calculate_authentication_score(self, email_analysis: Dict[str, Any]) -> float:
        """Calculate email authentication score."""
        auth_results = email_analysis.get('authentication_results', {})
        score = 0.0
        weights = {'spf': 0.4, 'dkim': 0.4, 'dmarc': 0.2}
        
        for mechanism, weight in weights.items():
            if auth_results.get(mechanism) == 'pass':
                score += weight
        
        return score

    def _calculate_domain_age(self, domain_analysis: Dict[str, Any]) -> float:
        """Calculate domain age in days."""
        try:
            creation_date = domain_analysis.get('creation_date')
            if creation_date:
                age = datetime.utcnow() - datetime.fromisoformat(creation_date)
                return age.days
            return 0.0
        except Exception:
            return 0.0

    def _calculate_ssl_validity(self, domain_analysis: Dict[str, Any]) -> float:
        """Calculate SSL certificate validity period in days."""
        try:
            ssl_info = domain_analysis.get('ssl_info', {})
            if ssl_info:
                not_after = datetime.strptime(ssl_info['not_after'], '%Y-%m-%d')
                validity = not_after - datetime.utcnow()
                return max(0.0, validity.days)
            return 0.0
        except Exception:
            return 0.0

    def _calculate_request_frequency(self, data: Dict[str, Any]) -> float:
        """Calculate request frequency score."""
        try:
            requests = data.get('request_history', [])
            if not requests:
                return 0.0
            
            time_diffs = []
            for i in range(1, len(requests)):
                t1 = datetime.fromisoformat(requests[i-1]['timestamp'])
                t2 = datetime.fromisoformat(requests[i]['timestamp'])
                time_diffs.append((t2 - t1).total_seconds())
            
            if time_diffs:
                return np.mean(time_diffs)
            return 0.0
        except Exception:
            return 0.0

    def _calculate_geographic_dispersion(self, data: Dict[str, Any]) -> float:
        """Calculate geographic dispersion score."""
        try:
            locations = data.get('ip_locations', [])
            unique_locations = set((loc['latitude'], loc['longitude']) for loc in locations)
            return len(unique_locations)
        except Exception:
            return 0.0

    def _calculate_time_pattern_score(self, data: Dict[str, Any]) -> float:
        """Calculate time pattern anomaly score."""
        try:
            timestamps = [
                datetime.fromisoformat(req['timestamp'])
                for req in data.get('request_history', [])
            ]
            
            if not timestamps:
                return 0.0
            
            # Calculate variance in hour of day
            hours = [ts.hour for ts in timestamps]
            return np.var(hours) if len(hours) > 1 else 0.0
        except Exception:
            return 0.0

    def _calculate_target_diversity(self, data: Dict[str, Any]) -> float:
        """Calculate target diversity score."""
        try:
            targets = data.get('target_addresses', [])
            unique_domains = set(email.split('@')[1] for email in targets if '@' in email)
            return len(unique_domains)
        except Exception:
            return 0.0

    def _calculate_technique_complexity(self, data: Dict[str, Any]) -> float:
        """Calculate technique complexity score."""
        try:
            techniques = set()
            if data.get('uses_url_obfuscation'):
                techniques.add('url_obfuscation')
            if data.get('uses_attachment'):
                techniques.add('attachment')
            if data.get('uses_urgency'):
                techniques.add('urgency')
            if data.get('uses_spoofing'):
                techniques.add('spoofing')
            
            return len(techniques)
        except Exception:
            return 0.0

    async def _detect_anomalies(self, feature_set: str, features: List[float]) -> Dict[str, Any]:
        """Detect anomalies in a feature set."""
        try:
            if feature_set not in self.models or feature_set not in self.scalers:
                return {
                    'is_anomaly': False,
                    'confidence': 0.0,
                    'anomalous_features': []
                }

            # Scale features
            scaled_features = self.scalers[feature_set].transform([features])
            
            # Get anomaly score (-1 for anomalies, 1 for normal)
            anomaly_score = self.models[feature_set].score_samples(scaled_features)[0]
            
            # Convert to probability-like score (0 to 1)
            confidence = 1 - (anomaly_score + 1) / 2
            
            # Identify anomalous features
            feature_scores = np.abs(scaled_features[0])
            anomalous_features = [
                {
                    'name': self.feature_sets[feature_set][i],
                    'score': float(feature_scores[i])
                }
                for i in range(len(feature_scores))
                if feature_scores[i] > 2.0  # More than 2 standard deviations
            ]

            return {
                'is_anomaly': confidence > 0.8,
                'confidence': float(confidence),
                'anomalous_features': anomalous_features
            }

        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {str(e)}")
            return {
                'is_anomaly': False,
                'confidence': 0.0,
                'anomalous_features': []
            }

    def _calculate_risk_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk assessment based on anomaly detection results."""
        assessment = {
            'risk_level': 'low',
            'confidence': 0.0,
            'risk_factors': []
        }

        try:
            # Calculate weighted anomaly scores
            weights = {
                'email': 0.4,
                'domain': 0.3,
                'behavior': 0.3
            }

            total_confidence = 0.0
            weighted_confidence = 0.0

            for feature_set, weight in weights.items():
                if feature_set in results['anomalies']:
                    anomaly_result = results['anomalies'][feature_set]
                    if anomaly_result['is_anomaly']:
                        assessment['risk_factors'].extend([
                            f"{feature_set}_{feature['name']}"
                            for feature in anomaly_result['anomalous_features']
                        ])
                    weighted_confidence += anomaly_result['confidence'] * weight
                    total_confidence += weight

            if total_confidence > 0:
                assessment['confidence'] = weighted_confidence / total_confidence

                # Determine risk level
                if assessment['confidence'] > 0.8:
                    assessment['risk_level'] = 'high'
                elif assessment['confidence'] > 0.5:
                    assessment['risk_level'] = 'medium'

        except Exception as e:
            self.logger.error(f"Error calculating risk assessment: {str(e)}")

        return assessment

    async def _notify_agents(self, incident_id: str, results: Dict[str, Any]) -> None:
        """Notify other agents about anomaly detection results."""
        try:
            # Notify the Phishing Score Agent
            await mq.publish('score_aggregation', {
                'incident_id': incident_id,
                'anomaly_detection_analysis': results
            })

            # Notify Alert Agent for high-risk anomalies
            if results['risk_level'] == 'high':
                await mq.publish('alert', {
                    'incident_id': incident_id,
                    'anomaly_alerts': {
                        'risk_level': results['risk_level'],
                        'confidence': results['confidence'],
                        'risk_factors': results['risk_factors']
                    },
                    'severity': 'high'
                })

        except Exception as e:
            self.logger.error(f"Error notifying agents: {str(e)}")

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Anomaly Detection Agent") 