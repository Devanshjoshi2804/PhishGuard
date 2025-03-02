from typing import Dict, Any, List
import spacy
from transformers import pipeline
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import re
import logging

class TextAnalysisAgent(BaseAgent):
    """Agent responsible for analyzing text content for phishing indicators."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("text_analysis", config)
        self.nlp = None
        self.sentiment_analyzer = None
        self.phishing_indicators = [
            r"urgent",
            r"account.*suspend",
            r"verify.*account",
            r"login.*details",
            r"security.*update",
            r"unusual.*activity",
            r"password.*expire",
            r"click.*link",
            r"limited.*time",
            r"immediate.*action",
        ]

    async def initialize(self) -> None:
        """Initialize the text analysis agent."""
        self.logger.info("Initializing Text Analysis Agent")
        try:
            # Load spaCy model
            self.nlp = spacy.load("en_core_web_sm")
            
            # Initialize sentiment analyzer
            self.sentiment_analyzer = pipeline(
                "sentiment-analysis",
                model="distilbert-base-uncased-finetuned-sst-2-english"
            )
            
            self.logger.info("Text Analysis Agent initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing Text Analysis Agent: {str(e)}")
            raise

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process text content for phishing indicators."""
        try:
            content = data.get('content', '')
            subject = data.get('subject', '')
            incident_id = data.get('incident_id')

            analysis_results = {
                'incident_id': incident_id,
                'text_indicators': await self._analyze_text(content, subject),
                'sentiment_analysis': await self._analyze_sentiment(content),
                'named_entities': await self._extract_entities(content),
                'urgency_score': self._calculate_urgency_score(content),
                'timestamp': data.get('timestamp')
            }

            # Store analysis results
            await db.update_analysis_result(incident_id, {
                'text_analysis': analysis_results
            })

            # Notify the Phishing Score Aggregation Agent
            await mq.publish('score_aggregation', {
                'incident_id': incident_id,
                'text_analysis': analysis_results
            })

            return analysis_results

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _analyze_text(self, content: str, subject: str) -> Dict[str, Any]:
        """Analyze text for phishing indicators."""
        indicators = []
        
        # Combine subject and content for analysis
        full_text = f"{subject}\n{content}".lower()
        
        # Check for phishing indicators
        for pattern in self.phishing_indicators:
            matches = re.finditer(pattern, full_text, re.IGNORECASE)
            for match in matches:
                indicators.append({
                    'pattern': pattern,
                    'match': match.group(),
                    'position': match.span()
                })

        return {
            'indicators_found': indicators,
            'indicator_count': len(indicators)
        }

    async def _analyze_sentiment(self, text: str) -> Dict[str, Any]:
        """Analyze the sentiment of the text."""
        try:
            result = self.sentiment_analyzer(text[:512])[0]  # Limit text length
            return {
                'label': result['label'],
                'score': result['score']
            }
        except Exception as e:
            self.logger.error(f"Error in sentiment analysis: {str(e)}")
            return {'label': 'UNKNOWN', 'score': 0.0}

    async def _extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """Extract named entities from the text."""
        doc = self.nlp(text)
        entities = []
        
        for ent in doc.ents:
            entities.append({
                'text': ent.text,
                'label': ent.label_,
                'start': ent.start_char,
                'end': ent.end_char
            })
        
        return entities

    def _calculate_urgency_score(self, text: str) -> float:
        """Calculate an urgency score based on urgent language patterns."""
        urgency_patterns = [
            r"urgent",
            r"immediate",
            r"now",
            r"quick",
            r"important",
            r"critical",
            r"limited time",
            r"expire",
            r"today",
            r"asap"
        ]
        
        text = text.lower()
        urgency_count = sum(len(re.findall(pattern, text, re.IGNORECASE)) 
                           for pattern in urgency_patterns)
        
        # Normalize score between 0 and 1
        max_expected_count = 10
        urgency_score = min(urgency_count / max_expected_count, 1.0)
        
        return urgency_score

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Text Analysis Agent")
        # Additional cleanup if needed 