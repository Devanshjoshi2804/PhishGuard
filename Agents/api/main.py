from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Dict, Any, List, Optional
import uuid
import logging
from datetime import datetime
import os
import sys
from pathlib import Path

from agents.ingestion.email_parser_agent import EmailParserAgent
from agents.analysis.url_analysis_agent import URLAnalysisAgent
from common.utils.database import db
from common.utils.message_queue import mq

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Phishing Detection System",
    description="API for detecting phishing attempts using multi-agent system",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailAnalysisRequest(BaseModel):
    email_content: str
    metadata: Optional[Dict[str, Any]] = None

class PhishingAnalysisResponse(BaseModel):
    incident_id: str
    status: str
    timestamp: str

class URLAnalysisRequest(BaseModel):
    urls: List[str]
    incident_id: Optional[str] = None

class URLAnalysisResponse(BaseModel):
    incident_id: Optional[str]
    analysis_time: str
    results: List[Dict[str, Any]]
    overall_risk_score: float

# Initialize agents
email_parser = EmailParserAgent({})

@app.on_event("startup")
async def startup_event():
    """Initialize components on startup."""
    await email_parser.initialize()
    logger.info("Phishing Detection System initialized")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    await email_parser.cleanup()
    logger.info("Phishing Detection System shut down")

@app.post("/analyze/email", response_model=PhishingAnalysisResponse)
async def analyze_email(
    request: EmailAnalysisRequest,
    background_tasks: BackgroundTasks
):
    """
    Analyze an email for phishing attempts.
    
    This endpoint initiates the analysis process by:
    1. Generating a unique incident ID
    2. Parsing the email content
    3. Triggering the analysis pipeline
    """
    try:
        incident_id = str(uuid.uuid4())
        
        # Start the analysis pipeline
        background_tasks.add_task(
            process_email_analysis,
            incident_id,
            request.email_content,
            request.metadata
        )
        
        return PhishingAnalysisResponse(
            incident_id=incident_id,
            status="processing",
            timestamp=datetime.utcnow().isoformat()
        )
    
    except Exception as e:
        logger.error(f"Error processing email analysis request: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/analysis/{incident_id}")
async def get_analysis_status(incident_id: str):
    """Get the status and results of an analysis."""
    try:
        result = await db.client.table('analysis_results').select('*').eq('incident_id', incident_id).execute()
        
        if not result.data:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        return result.data[0]
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving analysis status: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

async def process_email_analysis(
    incident_id: str,
    email_content: str,
    metadata: Optional[Dict[str, Any]] = None
):
    """Process email analysis in the background."""
    try:
        # Parse email
        parsed_data = await email_parser.process({
            'incident_id': incident_id,
            'email_content': email_content,
            'metadata': metadata
        })
        
        logger.info(f"Email parsed successfully for incident {incident_id}")
        
        # The rest of the pipeline will be triggered through the message queue
        # as implemented in the EmailParserAgent
        
    except Exception as e:
        logger.error(f"Error in email analysis pipeline for incident {incident_id}: {str(e)}")
        await db.update_analysis_result(incident_id, {
            'status': 'error',
            'error_message': str(e),
            'timestamp': datetime.utcnow().isoformat()
        })

@app.post("/analyze/url", response_model=URLAnalysisResponse)
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze one or more URLs for phishing indicators.
    
    This endpoint will:
    1. Process the provided URLs
    2. Check for various phishing indicators
    3. Calculate a risk score
    4. Store the results if an incident_id is provided
    """
    try:
        # Initialize URL analysis agent with configuration
        config = {
            'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.date', '.faith'],
            'suspicious_keywords': ['login', 'signin', 'account', 'secure', 'verify', 'update', 'confirm',
                                 'banking', 'password', 'credential', 'wallet', 'payment'],
            'max_redirects': 5,
            'timeout': 10
        }
        agent = URLAnalysisAgent(config)
        await agent.initialize()
        
        # Process URLs
        analysis_result = await agent.process({
            'urls': request.urls,
            'incident_id': request.incident_id
        })
        
        # Clean up agent resources
        await agent.cleanup()
        
        # Prepare response
        return URLAnalysisResponse(
            incident_id=request.incident_id,
            analysis_time=datetime.now().isoformat(),
            results=analysis_result['url_analysis']['results'],
            overall_risk_score=analysis_result['url_analysis']['overall_risk_score']
        )
        
    except Exception as e:
        logger.error(f"Error analyzing URLs: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing URLs: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 