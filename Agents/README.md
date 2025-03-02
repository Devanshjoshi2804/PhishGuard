# Phishing Detection Agent System

An intelligent multi-agent system for detecting and preventing phishing attempts using advanced ML/AI techniques.

## System Components

### Ingestion & Preprocessing Agents
- Email Parser Agent
- Web Scraper Agent
- Messaging Content Extractor Agent
- OCR Agent

### Feature Extraction & Analysis Agents
- Text Analysis Agent
- URL & Link Analysis Agent
- Metadata Extraction Agent
- Domain Reputation & History Agent

### Threat Intelligence & Scoring Agents
- Threat Intelligence Agent
- Anomaly Detection Agent
- Phishing Score Aggregation Agent

### Decision & Response Agents
- Alert & Notification Agent
- Auto-Response Agent
- Reinforcement Learning Agent

### Logging & Monitoring Agents
- Logging & Reporting Agent
- Feedback Learning Agent

## Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```
4. Run the development server:
   ```bash
   uvicorn main:app --reload
   ```

## Environment Variables

Create a `.env` file with the following variables:
- `SUPABASE_URL`: Your Supabase project URL
- `SUPABASE_KEY`: Your Supabase project API key
- `REDIS_URL`: Redis connection URL
- `ENVIRONMENT`: Development/Production

## Development

### Running Tests
```bash
pytest
```

### Adding New Agents
1. Create a new agent class in the appropriate directory under `agents/`
2. Implement the required interface methods
3. Register the agent in the main configuration

## Deployment

The system is configured for deployment on Vercel. Follow these steps:
1. Connect your repository to Vercel
2. Configure environment variables in Vercel dashboard
3. Deploy! 