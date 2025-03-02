from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
import json
from datetime import datetime
import re

class MessageExtractorAgent(BaseAgent):
    """Agent responsible for extracting and analyzing content from various messaging sources."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("message_extractor", config)
        self.supported_platforms = {
            'sms': self._process_sms,
            'whatsapp': self._process_whatsapp,
            'telegram': self._process_telegram,
            'facebook': self._process_facebook,
            'twitter': self._process_twitter,
            'slack': self._process_slack,
            'discord': self._process_discord,
            'generic': self._process_generic_chat
        }

    async def initialize(self) -> None:
        """Initialize the message extractor agent."""
        self.logger.info("Initializing Message Extractor Agent")

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process messaging content from various platforms."""
        try:
            incident_id = data.get('incident_id')
            platform = data.get('platform', 'generic').lower()
            content = data.get('content')
            
            if not content:
                raise ValueError("No message content provided")

            if platform not in self.supported_platforms:
                self.logger.warning(f"Unsupported platform: {platform}, using generic processor")
                platform = 'generic'

            # Process the content using the appropriate handler
            processor = self.supported_platforms[platform]
            analysis_results = await processor(content)
            
            # Add metadata
            analysis_results.update({
                'incident_id': incident_id,
                'platform': platform,
                'timestamp': datetime.utcnow().isoformat()
            })

            # Store results
            await db.update_analysis_result(incident_id, {
                'message_analysis': analysis_results
            })

            # Notify other agents
            await self._notify_agents(incident_id, analysis_results)

            return analysis_results

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _process_sms(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Process SMS messages."""
        try:
            messages = content.get('messages', [])
            processed_messages = []

            for msg in messages:
                processed_msg = {
                    'sender': msg.get('sender'),
                    'recipient': msg.get('recipient'),
                    'timestamp': msg.get('timestamp'),
                    'text': msg.get('text', ''),
                    'metadata': {
                        'message_type': 'sms',
                        'carrier': msg.get('carrier'),
                        'device_info': msg.get('device_info')
                    }
                }
                processed_messages.append(processed_msg)

            return {
                'messages': processed_messages,
                'message_count': len(processed_messages),
                'platform_specific': {
                    'has_mms': any('mms_content' in msg for msg in messages)
                }
            }
        except Exception as e:
            self.logger.error(f"Error processing SMS content: {str(e)}")
            raise

    async def _process_whatsapp(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Process WhatsApp messages."""
        try:
            messages = content.get('messages', [])
            processed_messages = []

            for msg in messages:
                processed_msg = {
                    'sender': msg.get('sender'),
                    'group_info': msg.get('group_info'),
                    'timestamp': msg.get('timestamp'),
                    'text': msg.get('text', ''),
                    'metadata': {
                        'message_type': msg.get('type', 'text'),
                        'forwarded': msg.get('forwarded', False),
                        'reply_to': msg.get('reply_to'),
                        'media_type': msg.get('media_type')
                    }
                }
                processed_messages.append(processed_msg)

            return {
                'messages': processed_messages,
                'message_count': len(processed_messages),
                'platform_specific': {
                    'is_group_chat': bool(content.get('group_info')),
                    'has_media': any(msg.get('media_type') for msg in messages)
                }
            }
        except Exception as e:
            self.logger.error(f"Error processing WhatsApp content: {str(e)}")
            raise

    async def _process_telegram(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Process Telegram messages."""
        try:
            messages = content.get('messages', [])
            processed_messages = []

            for msg in messages:
                processed_msg = {
                    'sender': msg.get('sender'),
                    'chat_info': msg.get('chat_info'),
                    'timestamp': msg.get('timestamp'),
                    'text': msg.get('text', ''),
                    'metadata': {
                        'message_type': msg.get('type', 'text'),
                        'forwarded_from': msg.get('forwarded_from'),
                        'reply_to_message': msg.get('reply_to_message'),
                        'entities': msg.get('entities', [])
                    }
                }
                processed_messages.append(processed_msg)

            return {
                'messages': processed_messages,
                'message_count': len(processed_messages),
                'platform_specific': {
                    'chat_type': content.get('chat_type', 'private'),
                    'has_bot_commands': any('bot_command' in msg.get('entities', []) for msg in messages)
                }
            }
        except Exception as e:
            self.logger.error(f"Error processing Telegram content: {str(e)}")
            raise

    async def _process_facebook(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Process Facebook messages."""
        try:
            messages = content.get('messages', [])
            processed_messages = []

            for msg in messages:
                processed_msg = {
                    'sender': msg.get('sender'),
                    'timestamp': msg.get('timestamp'),
                    'text': msg.get('text', ''),
                    'metadata': {
                        'message_type': msg.get('type', 'text'),
                        'reactions': msg.get('reactions', []),
                        'shares': msg.get('shares', []),
                        'attachments': msg.get('attachments', [])
                    }
                }
                processed_messages.append(processed_msg)

            return {
                'messages': processed_messages,
                'message_count': len(processed_messages),
                'platform_specific': {
                    'conversation_type': content.get('conversation_type'),
                    'participant_count': len(set(msg['sender'] for msg in messages))
                }
            }
        except Exception as e:
            self.logger.error(f"Error processing Facebook content: {str(e)}")
            raise

    async def _process_twitter(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Process Twitter messages."""
        try:
            messages = content.get('messages', [])
            processed_messages = []

            for msg in messages:
                processed_msg = {
                    'sender': msg.get('sender'),
                    'timestamp': msg.get('timestamp'),
                    'text': msg.get('text', ''),
                    'metadata': {
                        'message_type': 'dm',
                        'media_entities': msg.get('media', []),
                        'urls': msg.get('urls', []),
                        'mentions': msg.get('mentions', [])
                    }
                }
                processed_messages.append(processed_msg)

            return {
                'messages': processed_messages,
                'message_count': len(processed_messages),
                'platform_specific': {
                    'has_media': any(msg.get('media') for msg in messages),
                    'mention_count': sum(len(msg.get('mentions', [])) for msg in messages)
                }
            }
        except Exception as e:
            self.logger.error(f"Error processing Twitter content: {str(e)}")
            raise

    async def _process_slack(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Process Slack messages."""
        try:
            messages = content.get('messages', [])
            processed_messages = []

            for msg in messages:
                processed_msg = {
                    'sender': msg.get('user'),
                    'timestamp': msg.get('ts'),
                    'text': msg.get('text', ''),
                    'metadata': {
                        'message_type': msg.get('type', 'message'),
                        'thread_ts': msg.get('thread_ts'),
                        'reactions': msg.get('reactions', []),
                        'files': msg.get('files', [])
                    }
                }
                processed_messages.append(processed_msg)

            return {
                'messages': processed_messages,
                'message_count': len(processed_messages),
                'platform_specific': {
                    'channel_type': content.get('channel_type'),
                    'has_threads': any(msg.get('thread_ts') for msg in messages),
                    'has_files': any(msg.get('files') for msg in messages)
                }
            }
        except Exception as e:
            self.logger.error(f"Error processing Slack content: {str(e)}")
            raise

    async def _process_discord(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Process Discord messages."""
        try:
            messages = content.get('messages', [])
            processed_messages = []

            for msg in messages:
                processed_msg = {
                    'sender': msg.get('author'),
                    'timestamp': msg.get('timestamp'),
                    'text': msg.get('content', ''),
                    'metadata': {
                        'message_type': msg.get('type', 'default'),
                        'attachments': msg.get('attachments', []),
                        'embeds': msg.get('embeds', []),
                        'mentions': msg.get('mentions', [])
                    }
                }
                processed_messages.append(processed_msg)

            return {
                'messages': processed_messages,
                'message_count': len(processed_messages),
                'platform_specific': {
                    'channel_type': content.get('channel_type'),
                    'has_attachments': any(msg.get('attachments') for msg in messages),
                    'has_embeds': any(msg.get('embeds') for msg in messages)
                }
            }
        except Exception as e:
            self.logger.error(f"Error processing Discord content: {str(e)}")
            raise

    async def _process_generic_chat(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Process generic chat messages."""
        try:
            messages = content if isinstance(content, list) else [content]
            processed_messages = []

            for msg in messages:
                # Handle both string messages and dictionary messages
                if isinstance(msg, str):
                    processed_msg = {
                        'text': msg,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                else:
                    processed_msg = {
                        'sender': msg.get('sender'),
                        'timestamp': msg.get('timestamp'),
                        'text': msg.get('text', msg.get('content', '')),
                        'metadata': {
                            'type': msg.get('type', 'text'),
                            'additional_data': msg.get('metadata', {})
                        }
                    }
                processed_messages.append(processed_msg)

            return {
                'messages': processed_messages,
                'message_count': len(processed_messages),
                'platform_specific': {
                    'format': 'generic',
                    'has_metadata': any('metadata' in msg for msg in processed_messages)
                }
            }
        except Exception as e:
            self.logger.error(f"Error processing generic chat content: {str(e)}")
            raise

    async def _notify_agents(self, incident_id: str, results: Dict[str, Any]) -> None:
        """Notify other agents about the extracted message content."""
        try:
            # Combine all message text for text analysis
            all_text = ' '.join(
                msg['text']
                for msg in results.get('messages', [])
                if msg.get('text')
            )

            if all_text.strip():
                # Notify Text Analysis Agent
                await mq.publish('text_analysis', {
                    'incident_id': incident_id,
                    'content': all_text,
                    'source': f"message_{results['platform']}"
                })

            # Extract and analyze URLs if present
            urls = self._extract_urls(all_text)
            if urls:
                await mq.publish('url_analysis', {
                    'incident_id': incident_id,
                    'urls': urls,
                    'source': f"message_{results['platform']}"
                })

        except Exception as e:
            self.logger.error(f"Error notifying agents: {str(e)}")

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text content."""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return list(set(re.findall(url_pattern, text)))

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Message Extractor Agent")
        # Additional cleanup if needed 