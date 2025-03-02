import os
import sys
import json
import uuid
import asyncio
from datetime import datetime
from pathlib import Path

# Add the project root to Python path
sys.path.append(str(Path(__file__).parent.parent))

from common.utils.database import db
from common.utils.message_queue import mq

async def test_phishing_detection_workflow():
    """Test the complete phishing detection workflow."""
    try:
        print("Initializing services...")
        await mq.connect()  # Initialize message queue (will work in mock mode if Redis is not available)
        
        print("\nStarting phishing detection workflow test...")
        
        # Generate a unique incident ID
        incident_id = f"TEST-{uuid.uuid4()}"
        
        # Test data
        test_email = {
            "raw_email": """
From: suspicious@example.com
To: victim@company.com
Subject: Urgent: Account Security Update Required

Dear User,

Your account security needs immediate attention. Click the link below to verify:
http://malicious-site.com/verify

Best regards,
Security Team
            """,
            "metadata": {
                "received_time": datetime.now().isoformat(),
                "source_ip": "192.168.1.100",
                "spam_score": 0.8
            }
        }
        
        # Store test incident in database
        print("Storing test incident...")
        incident = await db.insert('phishing_incidents', {
            'incident_id': incident_id,
            'status': 'new',
            'risk_level': 'unknown',
            'source': 'test',
            'raw_data': {'email': test_email['raw_email']},
            'metadata': test_email['metadata']
        })
        print("✓ Test incident stored successfully")
        
        # Simulate analysis results
        print("Storing analysis results...")
        analysis_result = {
            'incident_id': incident_id,
            'text_analysis': {
                'sentiment': 'negative',
                'urgency_indicators': True,
                'suspicious_patterns': ['click_link', 'urgent_action']
            },
            'url_analysis': {
                'urls_found': ['http://malicious-site.com/verify'],
                'malicious_score': 0.9
            }
        }
        
        await db.insert('analysis_results', analysis_result)
        print("✓ Analysis results stored successfully")
        
        # Simulate agent communication
        print("Testing agent communication...")
        await mq.publish('text_analysis', {
            'incident_id': incident_id,
            'content': test_email['raw_email']
        })
        print("✓ Agent communication test completed")
        
        # Store test feedback
        print("Storing test feedback...")
        feedback = {
            'incident_id': incident_id,
            'feedback_type': 'automated',
            'is_phishing': True,
            'confidence': 0.95,
            'features': {
                'has_urgent_language': True,
                'has_suspicious_links': True
            },
            'metadata': {
                'source': 'test_workflow',
                'timestamp': datetime.now().isoformat()
            }
        }
        
        await db.insert('feedback_data', feedback)
        print("✓ Test feedback stored successfully")
        
        # Save test results
        results = {
            'test_time': datetime.now().isoformat(),
            'incident_id': incident_id,
            'incident': incident,
            'analysis': analysis_result,
            'feedback': feedback
        }
        
        os.makedirs('reports', exist_ok=True)
        with open('reports/test_workflow_results.json', 'w') as f:
            json.dump(results, f, indent=2)
            
        print("\n✨ Workflow test completed successfully!")
        print("Results saved to reports/test_workflow_results.json")
        
    except Exception as e:
        print(f"❌ Error during workflow test: {str(e)}")
        raise
    finally:
        await mq.cleanup()

if __name__ == "__main__":
    asyncio.run(test_phishing_detection_workflow()) 