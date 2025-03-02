import sys
import os
import time

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from agents.ingestion.email_parser_agent import EmailParserAgent
from agents.analysis.metadata_agent import MetadataAgent
from agents.analysis.url_analysis_agent import URLAnalysisAgent
from agents.intelligence.phishing_score_agent import PhishingScoreAgent
from dotenv import load_dotenv

load_dotenv()

# More sophisticated phishing email sample
SAMPLE_EMAIL = '''From: "PayPal Security Team" <security@paypaI-secure-login.com>
Reply-To: "Support Team" <support@paypaI-secure-center.com>
To: victim@company.com
Subject: ⚠️ Urgent: Unauthorized Access Detected - Immediate Action Required
Date: Thu, 20 Jul 2023 10:00:00 -0700
Message-ID: <1234567890.987654321@paypaI-secure-login.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary_string"
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
    by mx.google.com with SMTPS id y4-20020a170902f14900b0016c7d1234567890
    for <victim@company.com>
    (Google Transport Security);
    Thu, 20 Jul 2023 10:00:00 -0700 (PDT)
Authentication-Results: mx.google.com;
    spf=fail (google.com: domain of security@paypaI-secure-login.com does not designate 209.85.220.41 as permitted sender) smtp.mailfrom=security@paypaI-secure-login.com;
    dkim=fail header.i=@paypaI-secure-login.com;
    dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypaI-secure-login.com

--boundary_string
Content-Type: text/plain; charset="UTF-8"

SECURITY ALERT: Unauthorized Login Attempt Detected

Dear Valued PayPal Customer,

We have detected multiple unauthorized login attempts to your PayPal account from an unrecognized device. For your security, your account access has been temporarily limited.

To restore full access to your account, please verify your identity immediately by clicking the secure link below:

https://secure-paypal-verification.com/restore-access?id=USER89763&token=a7b8c9

If you do not verify your account within 24 hours, it will be permanently suspended.

For additional security measures, please have the following information ready:
- Your PayPal email and password
- Credit card information
- Bank account details
- Social Security Number (US customers)

DO NOT IGNORE THIS EMAIL - Your immediate action is required.

Security Team
PayPal

--boundary_string
Content-Type: text/html; charset="UTF-8"

<html>
<head>
<style>
.header { color: #1e477c; font-size: 20px; font-weight: bold; }
.warning { color: red; font-weight: bold; }
.button { background-color: #0070ba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
.hidden { display: none; }
</style>
</head>
<body style="font-family: Arial, sans-serif;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <img src="https://cdn-paypal-logos.com/images/logo.png" alt="PayPal" style="width: 150px;" />
    <div class="hidden">paypal-secure-verification-center</div>
    
    <h1 class="header">⚠️ SECURITY ALERT: Unauthorized Login Attempt Detected</h1>
    
    <p>Dear Valued PayPal Customer,</p>

    <p class="warning">We have detected multiple unauthorized login attempts to your PayPal account from an unrecognized device:</p>
    
    <ul>
        <li>Location: Moscow, Russia</li>
        <li>IP Address: 185.127.xxx.xxx</li>
        <li>Device: Unknown Android Device</li>
        <li>Time: July 20, 2023 09:45:23 UTC</li>
    </ul>

    <p>For your security, your account access has been temporarily limited.</p>

    <p style="font-weight: bold;">To restore full access to your account, please verify your identity immediately:</p>

    <p style="text-align: center; margin: 30px 0;">
        <a href="https://secure-paypal-verification.com/restore-access?id=USER89763&token=a7b8c9" class="button">
            Verify Account Now
        </a>
    </p>

    <div style="display: none;">
        <img src="https://tracking-pixel.com/track?id=USER89763" width="1" height="1" />
        <a href="https://malicious-backup-domain.com/restore?id=USER89763">Backup verification link</a>
    </div>

    <p style="color: red; font-weight: bold;">If you do not verify your account within 24 hours, it will be permanently suspended.</p>

    <p>For additional security measures, please have the following information ready:</p>
    <ul>
        <li>Your PayPal email and password</li>
        <li>Credit card information</li>
        <li>Bank account details</li>
        <li>Social Security Number (US customers)</li>
    </ul>

    <script type="text/javascript">
    eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('d a=["\\b\\3\\4\\5\\6\\7\\2\\8\\9\\c\\e","\\f\\g\\h\\i\\j\\k\\l"];',22,22,'||x61|x76|x69|x67|x61|x74|x6f|x72||x6e|x0a|var|x72|x77|x69|x6e|x64|x6f|x77|x0a'.split('|'),0,{}))
    </script>

    <hr style="margin: 30px 0;" />
    
    <p style="font-size: 12px; color: #666;">
        This is an automated message from PayPal. Please do not reply to this email. For assistance, log in to your PayPal account and visit the Help Center.
    </p>
</div>
</body>
</html>

--boundary_string--
'''

async def test_email_analysis():
    try:
        # Generate a unique incident ID
        incident_id = f"TEST-{int(time.time())}"
        
        # Initialize agents
        config = {
            'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.gq'],
            'suspicious_keywords': ['verify', 'suspend', 'unusual activity', 'security', 'urgent'],
        }
        
        email_parser = EmailParserAgent("email_parser", config)
        metadata_agent = MetadataAgent("metadata", config)
        url_analysis_agent = URLAnalysisAgent("url_analysis", config)
        phishing_score_agent = PhishingScoreAgent("phishing_score", config)
        
        # Initialize agents
        await email_parser.initialize()
        await metadata_agent.initialize()
        await url_analysis_agent.initialize()
        await phishing_score_agent.initialize()
        
        print("\n1. Testing Email Parser Agent...")
        email_results = await email_parser.process({
            'incident_id': incident_id,
            'email_content': SAMPLE_EMAIL
        })
        print("✓ Email parsed successfully")
        print(f"- Headers extracted: {list(email_results['headers'].keys())}")
        print(f"- URLs found: {len(email_results.get('urls', []))}")
        
        print("\n2. Testing Metadata Analysis...")
        metadata_results = await metadata_agent.process({
            'incident_id': incident_id,
            'metadata': {
                'headers': email_results['headers'],
                'urls': email_results['urls']
            }
        })
        print("✓ Metadata analysis completed")
        if metadata_results.get('headers_analysis'):
            print(f"- Header analysis: {metadata_results['headers_analysis']}")
        if metadata_results.get('authentication_analysis'):
            print(f"- Authentication analysis: {metadata_results['authentication_analysis']}")
        
        print("\n3. Testing URL Analysis...")
        url_results = await url_analysis_agent.process({
            'incident_id': incident_id,
            'urls': email_results.get('urls', [])
        })
        print("✓ URL analysis completed")
        for result in url_results.get('url_analysis', {}).get('results', []):
            print(f"- URL: {result['url']}")
            print(f"- Risk Score: {result.get('risk_score', 0):.2f}")
        
        print("\n4. Testing Phishing Score Calculation...")
        final_results = await phishing_score_agent.process({
            'incident_id': incident_id
        })
        print("✓ Phishing score calculation completed")
        print(f"- Final Risk Score: {final_results.get('overall_score', 0):.2f}")
        print(f"- Risk Level: {final_results.get('risk_level', 'unknown')}")
        
        # Cleanup
        await email_parser.cleanup()
        await metadata_agent.cleanup()
        await url_analysis_agent.cleanup()
        await phishing_score_agent.cleanup()
        
    except Exception as e:
        print(f"Error during testing: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(test_email_analysis()) 