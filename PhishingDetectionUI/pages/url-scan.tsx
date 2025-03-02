import React, { useState } from 'react';
import Head from 'next/head';
import Layout from '../components/Layout';
import LinkScanner from '../components/LinkScanner';
import LinkScanResult, { LinkAnalysisResult } from '../components/LinkScanResult';
import { motion } from 'framer-motion';
import { ShieldCheckIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';

export default function UrlScanPage() {
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<LinkAnalysisResult | null>(null);
  
  const handleScanUrl = async (url: string) => {
    setIsScanning(true);
    
    try {
      // In a real implementation, you would call your API here
      // const response = await fetch('/api/analyze/url', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ url })
      // });
      // const data = await response.json();
      
      // For demo purposes, we'll simulate an API call with setTimeout
      await new Promise(resolve => setTimeout(resolve, 3500));
      
      // Generate mock result with varying values based on the URL
      const isSuspiciousUrl = url.includes('suspicious') || 
                             url.includes('verify') || 
                             url.includes('login') || 
                             url.includes('account') ||
                             url.includes('secure') ||
                             !url.startsWith('https');
      
      const isHighRiskUrl = url.includes('banking') || 
                           url.includes('financial') || 
                           url.includes('wallet') ||
                           url.endsWith('.info') ||
                           url.includes('document');
      
      const domainAge = isHighRiskUrl ? 
                        Math.floor(Math.random() * 25) + 1 : // 1-25 days for high risk
                        isSuspiciousUrl ? 
                        Math.floor(Math.random() * 150) + 30 : // 30-180 days for suspicious
                        Math.floor(Math.random() * 1000) + 200; // 200-1200 days for others
      
      const safetyScore = isHighRiskUrl ? 
                         Math.floor(Math.random() * 25) + 10 : // 10-35
                         isSuspiciousUrl ? 
                         Math.floor(Math.random() * 30) + 40 : // 40-70
                         Math.floor(Math.random() * 25) + 75; // 75-100
      
      const verdict: 'safe' | 'suspicious' | 'malicious' = 
        safetyScore >= 70 ? 'safe' : 
        safetyScore >= 40 ? 'suspicious' : 
        'malicious';
      
      const sslValid = url.startsWith('https') || (!isSuspiciousUrl && !isHighRiskUrl);
      
      const threatIndicators = [
        {
          name: 'Domain Reputation',
          value: isHighRiskUrl ? 25 : isSuspiciousUrl ? 60 : 95,
          status: isHighRiskUrl ? 'danger' as const : isSuspiciousUrl ? 'warning' as const : 'safe' as const,
          description: isHighRiskUrl ? 
                      'Domain has been reported as malicious in multiple threat databases' : 
                      isSuspiciousUrl ? 
                      'Domain has some suspicious characteristics but no confirmed malicious activity' : 
                      'Domain has good reputation and no known security issues'
        },
        {
          name: 'SSL Certificate',
          value: sslValid ? 95 : 30,
          status: sslValid ? 'safe' as const : 'danger' as const,
          description: sslValid ? 
                      'Valid SSL certificate issued by a trusted authority' : 
                      'Missing or invalid SSL certificate'
        },
        {
          name: 'Link Structure',
          value: url.includes('id=') || url.includes('?') ? 55 : 85,
          status: url.includes('id=') || url.includes('?') ? 'warning' as const : 'safe' as const,
          description: url.includes('id=') || url.includes('?') ? 
                      'URL contains parameters that might be used for tracking or redirect purposes' : 
                      'URL structure appears clean and straightforward'
        },
        {
          name: 'Content Analysis',
          value: isHighRiskUrl ? 20 : isSuspiciousUrl ? 50 : 90,
          status: isHighRiskUrl ? 'danger' as const : isSuspiciousUrl ? 'warning' as const : 'safe' as const,
          description: isHighRiskUrl ? 
                      'Page content contains multiple high-risk elements typical of phishing sites' : 
                      isSuspiciousUrl ? 
                      'Some elements in the page content match known suspicious patterns' : 
                      'Content appears legitimate with no suspicious elements detected'
        },
        {
          name: 'Blacklist Status',
          value: isHighRiskUrl ? 25 : isSuspiciousUrl ? 70 : 100,
          status: isHighRiskUrl ? 'danger' as const : isSuspiciousUrl ? 'warning' as const : 'safe' as const,
          description: isHighRiskUrl ? 
                      'Domain is blacklisted in several security databases' : 
                      isSuspiciousUrl ? 
                      'Domain is watchlisted but not confirmed malicious' : 
                      'Domain is not present in any known blacklists'
        }
      ];
      
      // Random registrars
      const registrars = [
        'GoDaddy.com, LLC', 
        'Namecheap, Inc.', 
        'Google Domains', 
        'Amazon Registrar, Inc.',
        'Domain.com, LLC',
        'NameSilo, LLC',
        'Tucows Domains Inc.'
      ];
      
      const mockResult: LinkAnalysisResult = {
        url,
        safetyScore,
        verdict,
        domainInfo: {
          age: domainAge,
          registrar: registrars[Math.floor(Math.random() * registrars.length)],
          expiryDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          isWhitelisted: !isSuspiciousUrl && !isHighRiskUrl,
          previouslyReported: isHighRiskUrl
        },
        sslInfo: {
          valid: sslValid,
          issuer: sslValid ? 
                 'DigiCert Inc' : 
                 'Unknown',
          expiryDate: sslValid ? 
                     new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] : 
                     '',
          strength: sslValid ? 
                   (url.includes('banking') ? 'strong' : 'medium') : 
                   'weak'
        },
        contentAnalysis: {
          hasMaliciousCode: isHighRiskUrl,
          hasPhishingPatterns: isHighRiskUrl || isSuspiciousUrl,
          hasSuspiciousForms: isHighRiskUrl || (isSuspiciousUrl && url.includes('login')),
          redirectCount: isHighRiskUrl ? 2 : isSuspiciousUrl ? 1 : 0
        },
        threatIndicators,
        scanDate: new Date().toLocaleString()
      };
      
      setScanResult(mockResult);
    } catch (error) {
      console.error('Error scanning URL:', error);
      // Handle error state here
    } finally {
      setIsScanning(false);
    }
  };
  
  return (
    <Layout>
      <Head>
        <title>URL Security Scanner | PhishGuard</title>
        <meta name="description" content="Analyze URLs for phishing and security threats" />
      </Head>
      
      <div className="mb-6">
        <h1 className="text-3xl font-bold">URL Security Scanner</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Analyze links for phishing attacks, malware, and other security threats
        </p>
      </div>
      
      <div className="space-y-6">
        <LinkScanner onScanUrl={handleScanUrl} isScanning={isScanning} />
        
        {scanResult && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <LinkScanResult result={scanResult} />
          </motion.div>
        )}
        
        {!scanResult && !isScanning && (
          <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70">
            <div className="flex items-center mb-4">
              <ShieldCheckIcon className="w-6 h-6 text-primary-500 mr-2" />
              <h2 className="text-xl font-bold">Why Use URL Scanning?</h2>
            </div>
            
            <div className="space-y-4">
              <p className="text-gray-600 dark:text-gray-300">
                Malicious URLs are a common vector for phishing attacks, malware distribution, and data theft. Our scanner helps you:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gray-50/80 dark:bg-gray-700/50 p-4 rounded-lg">
                  <h3 className="font-medium mb-2">Avoid Phishing Sites</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Detect fake websites designed to steal your credentials or personal information.
                  </p>
                </div>
                
                <div className="bg-gray-50/80 dark:bg-gray-700/50 p-4 rounded-lg">
                  <h3 className="font-medium mb-2">Prevent Malware</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Identify URLs that may download malicious software to your device.
                  </p>
                </div>
                
                <div className="bg-gray-50/80 dark:bg-gray-700/50 p-4 rounded-lg">
                  <h3 className="font-medium mb-2">Verify Legitimacy</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Confirm that links from emails and messages are safe before clicking.
                  </p>
                </div>
                
                <div className="bg-gray-50/80 dark:bg-gray-700/50 p-4 rounded-lg">
                  <h3 className="font-medium mb-2">Protect Sensitive Data</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Ensure your personal and financial information isn't sent to untrusted sources.
                  </p>
                </div>
              </div>
              
              <div className="flex items-center p-4 bg-primary-50/70 dark:bg-primary-900/20 rounded-lg text-sm">
                <ExclamationTriangleIcon className="w-5 h-5 text-primary-500 mr-2 flex-shrink-0" />
                <p className="text-primary-700 dark:text-primary-300">
                  Always verify URLs before entering sensitive information or downloading content, especially from unexpected sources.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
} 