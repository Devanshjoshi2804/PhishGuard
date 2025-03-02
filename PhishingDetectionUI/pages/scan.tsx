import React, { useState } from 'react';
import Head from 'next/head';
import Layout from '../components/Layout';
import EmailScanner from '../components/EmailScanner';
import PhishingScoreCard from '../components/PhishingScoreCard';
import ProcessMonitor from '../components/ProcessMonitor';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  LinkIcon,
  MagnifyingGlassIcon,
  FingerPrintIcon,
  ShieldExclamationIcon,
  ArrowPathIcon,
  GlobeAltIcon,
  ArrowTopRightOnSquareIcon
} from '@heroicons/react/24/outline';

export default function ScanPage() {
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<null | {
    score: number;
    details: { category: string; score: number; description: string }[];
    urls: Array<{url: string; risk: 'high' | 'medium' | 'low'; reason: string}>;
    verdict: 'safe' | 'suspicious' | 'malicious';
    scanTime: string;
  }>(null);
  
  const handleScanEmail = async (emailContent: string) => {
    setIsScanning(true);
    setScanResult(null);
    
    // Simulate API call to backend
    try {
      // In a real app, this would be an API call to your backend
      // const response = await fetch('/api/analyze/email', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ email_content: emailContent })
      // });
      // const data = await response.json();
      
      // For demo purposes, simulate a delay and return mock data
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      // Mock response data
      const scanTime = new Date().toISOString();
      const score = Math.floor(Math.random() * 40) + 60; // Random score between 60-100
      
      // Create random details with improved labels
      const detailsCategories = [
        {category: 'Content Analysis', description: 'Analysis of email text and structure'},
        {category: 'URL Security', description: 'Evaluation of embedded links'},
        {category: 'Domain Verification', description: 'Authenticity of sender domain'},
        {category: 'Sender Reputation', description: 'Trust score of sender address'}
      ];
      
      const details = detailsCategories.map(item => ({
        category: item.category,
        score: Math.floor(Math.random() * 50) + 50,
        description: item.description
      }));
      
      // Generate suspicious URLs
      const urlDomains = [
        'suspicious-banking.com',
        'account-verify-now.net',
        'secure-login-portal.info',
        'document-share.cc',
        'tracking-delivery.co'
      ];
      
      const urlPaths = [
        '/login',
        '/verify',
        '/account/secure',
        '/document/view',
        '/reset-password'
      ];
      
      const urlReasons = [
        'Domain registered recently',
        'Suspicious URL pattern',
        'Known phishing domain',
        'Redirect to malicious content',
        'Request for sensitive information'
      ];
      
      const urls = Array(3).fill(null).map(() => {
        const domain = urlDomains[Math.floor(Math.random() * urlDomains.length)];
        const path = urlPaths[Math.floor(Math.random() * urlPaths.length)];
        const reason = urlReasons[Math.floor(Math.random() * urlReasons.length)];
        const riskValue = Math.random();
        const risk: 'high' | 'medium' | 'low' = riskValue > 0.7 ? 'high' : (riskValue > 0.5 ? 'medium' : 'low');
        
        return {
          url: `http://${domain}${path}`,
          risk,
          reason
        };
      });
      
      // Determine verdict based on score
      let verdict: 'safe' | 'suspicious' | 'malicious';
      if (score < 30) verdict = 'safe';
      else if (score < 70) verdict = 'suspicious';
      else verdict = 'malicious';
      
      setScanResult({
        score,
        details,
        urls,
        verdict,
        scanTime
      });
    } catch (error) {
      console.error('Error scanning email:', error);
      // Handle error state
    } finally {
      setIsScanning(false);
    }
  };
  
  const getVerdictColor = (verdict?: 'safe' | 'suspicious' | 'malicious') => {
    switch (verdict) {
      case 'safe': return 'bg-success-100 text-success-800 dark:bg-success-900/50 dark:text-success-100';
      case 'suspicious': return 'bg-warning-100 text-warning-800 dark:bg-warning-900/50 dark:text-warning-100';
      case 'malicious': return 'bg-danger-100 text-danger-800 dark:bg-danger-900/50 dark:text-danger-100';
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100';
    }
  };
  
  const getVerdictIcon = (verdict?: 'safe' | 'suspicious' | 'malicious') => {
    switch (verdict) {
      case 'safe': return <CheckCircleIcon className="w-6 h-6 text-success-500" />;
      case 'suspicious': return <ExclamationTriangleIcon className="w-6 h-6 text-warning-500" />;
      case 'malicious': return <XCircleIcon className="w-6 h-6 text-danger-500" />;
      default: return <ShieldCheckIcon className="w-6 h-6 text-gray-500" />;
    }
  };
  
  const getRiskColor = (risk: 'high' | 'medium' | 'low') => {
    switch (risk) {
      case 'high': return 'bg-danger-100 text-danger-800 dark:bg-danger-900/50 dark:text-danger-100';
      case 'medium': return 'bg-warning-100 text-warning-800 dark:bg-warning-900/50 dark:text-warning-100';
      case 'low': return 'bg-gray-100 text-gray-800 dark:bg-gray-700/50 dark:text-gray-300';
    }
  };
  
  return (
    <Layout>
      <Head>
        <title>PhishGuard - Email Scanner</title>
        <meta name="description" content="Scan emails for phishing attempts with advanced detection technology" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      
      <div className="mb-6">
        <h1 className="text-3xl font-bold">Email Scanner</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Scan emails for phishing attempts with real-time analysis
        </p>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <EmailScanner onScanEmail={handleScanEmail} isScanning={isScanning} />
        </div>
        
        <div>
          {scanResult ? (
            <PhishingScoreCard 
              score={scanResult.score} 
              details={scanResult.details} 
            />
          ) : (
            <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70 h-full flex flex-col items-center justify-center text-center">
              <div className="relative w-16 h-16 mb-4">
                <div className="absolute inset-0 bg-primary-500/20 rounded-full filter blur-md"></div>
                <div className="w-16 h-16 rounded-full bg-primary-100/80 dark:bg-primary-900/50 flex items-center justify-center relative z-10">
                  <MagnifyingGlassIcon className="w-8 h-8 text-primary-500" />
                </div>
              </div>
              <h3 className="text-xl font-semibold mb-2">No Scan Results</h3>
              <p className="text-gray-500 dark:text-gray-400 mb-4 max-w-xs">
                Paste an email in the scanner to analyze it for phishing attempts and get real-time results
              </p>
              <div className="flex flex-wrap justify-center gap-2 mt-2">
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-100">
                  <FingerPrintIcon className="w-3.5 h-3.5 mr-1" />
                  Content Analysis
                </span>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-100">
                  <LinkIcon className="w-3.5 h-3.5 mr-1" />
                  URL Analysis
                </span>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-100">
                  <GlobeAltIcon className="w-3.5 h-3.5 mr-1" />
                  Domain Check
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {scanResult && (
        <motion.div 
          className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-6"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="lg:col-span-2">
            <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70">
              <h3 className="text-xl font-semibold mb-4 flex items-center">
                <LinkIcon className="w-5 h-5 mr-2 text-primary-500" />
                Detected URLs
              </h3>
              
              <div className="space-y-3">
                <AnimatePresence>
                  {scanResult.urls.map((url, index) => (
                    <motion.div 
                      key={url.url}
                      className="p-3 border border-gray-200/70 dark:border-gray-700/70 rounded-lg backdrop-blur-sm"
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                    >
                      <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                        <div className="flex items-center">
                          <div className="flex-shrink-0 w-10 h-10 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center mr-3">
                            <GlobeAltIcon className="w-6 h-6 text-gray-500" />
                          </div>
                          <div className="truncate">
                            <div className="flex items-center space-x-2">
                              <span className="font-medium break-all">{url.url}</span>
                              <button className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                                <ArrowTopRightOnSquareIcon className="w-4 h-4" />
                              </button>
                            </div>
                            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                              {url.reason}
                            </p>
                          </div>
                        </div>
                        <span className={`ml-2 px-2.5 py-1 text-xs font-medium rounded-full ${getRiskColor(url.risk)} flex-shrink-0`}>
                          {url.risk === 'high' && <ShieldExclamationIcon className="w-3.5 h-3.5 mr-1" />}
                          {url.risk.charAt(0).toUpperCase() + url.risk.slice(1)} Risk
                        </span>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>
            </div>
          </div>
          
          <div>
            <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70">
              <h3 className="text-xl font-semibold mb-4 flex items-center">
                <ShieldCheckIcon className="w-5 h-5 mr-2 text-primary-500" />
                Analysis Verdict
              </h3>
              
              <div className={`p-4 rounded-lg ${getVerdictColor(scanResult.verdict)}`}>
                <div className="flex items-center mb-2">
                  {getVerdictIcon(scanResult.verdict)}
                  <span className="ml-2 font-bold capitalize">{scanResult.verdict}</span>
                </div>
                <p className="text-sm">
                  {scanResult.verdict === 'malicious' && 'This email contains malicious content and should be treated as a phishing attempt.'}
                  {scanResult.verdict === 'suspicious' && 'This email contains suspicious elements and should be treated with caution.'}
                  {scanResult.verdict === 'safe' && 'This email appears to be safe, but always exercise caution.'}
                </p>
              </div>
              
              <div className="mt-4">
                <h4 className="font-medium mb-2">Recommendations:</h4>
                <ul className="space-y-2 text-sm">
                  {scanResult.verdict !== 'safe' && (
                    <>
                      <li className="flex items-start">
                        <XCircleIcon className="w-5 h-5 text-danger-500 mr-2 flex-shrink-0 mt-0.5" />
                        <span>Do not click on any links in this email</span>
                      </li>
                      <li className="flex items-start">
                        <XCircleIcon className="w-5 h-5 text-danger-500 mr-2 flex-shrink-0 mt-0.5" />
                        <span>Do not download any attachments</span>
                      </li>
                      <li className="flex items-start">
                        <XCircleIcon className="w-5 h-5 text-danger-500 mr-2 flex-shrink-0 mt-0.5" />
                        <span>Do not reply to this email</span>
                      </li>
                    </>
                  )}
                  <li className="flex items-start">
                    <CheckCircleIcon className="w-5 h-5 text-success-500 mr-2 flex-shrink-0 mt-0.5" />
                    <span>{scanResult.verdict === 'safe' ? 'Safe to proceed, but remain vigilant' : 'Report this email to your IT department'}</span>
                  </li>
                </ul>
              </div>
              
              <div className="mt-6 pt-4 border-t border-gray-200/70 dark:border-gray-700/70">
                <div className="flex justify-between items-center text-xs text-gray-500 dark:text-gray-400">
                  <span>
                    Scan completed: {new Date(scanResult.scanTime).toLocaleTimeString()}
                  </span>
                  <motion.button 
                    className="text-primary-500 hover:text-primary-600 font-medium flex items-center"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={() => setScanResult(null)}
                  >
                    <ArrowPathIcon className="h-4 w-4 mr-1" />
                    New Scan
                  </motion.button>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      )}
      
      {scanResult && (
        <motion.div 
          className="mt-6 bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-semibold flex items-center">
              <FingerPrintIcon className="w-5 h-5 mr-2 text-primary-500" /> 
              Scan Details
            </h3>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              Scan ID: {Math.random().toString(36).substring(2, 10).toUpperCase()}
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-50/80 dark:bg-gray-700/50 p-4 rounded-lg">
              <div className="text-sm text-gray-500 dark:text-gray-400 mb-1">Scan Type</div>
              <div className="font-medium">Email Content Analysis</div>
            </div>
            <div className="bg-gray-50/80 dark:bg-gray-700/50 p-4 rounded-lg">
              <div className="text-sm text-gray-500 dark:text-gray-400 mb-1">Processing Time</div>
              <div className="font-medium">{(Math.random() * 2 + 0.5).toFixed(2)}s</div>
            </div>
            <div className="bg-gray-50/80 dark:bg-gray-700/50 p-4 rounded-lg">
              <div className="text-sm text-gray-500 dark:text-gray-400 mb-1">Links Analyzed</div>
              <div className="font-medium">{scanResult.urls.length}</div>
            </div>
            <div className="bg-gray-50/80 dark:bg-gray-700/50 p-4 rounded-lg">
              <div className="text-sm text-gray-500 dark:text-gray-400 mb-1">Confidence Score</div>
              <div className="font-medium">{Math.floor(90 + Math.random() * 9)}%</div>
            </div>
          </div>
          
          <div className="flex items-center justify-between">
            <button className="text-primary-500 hover:text-primary-600 dark:hover:text-primary-400 font-medium">
              Download Full Report
            </button>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              Powered by advanced threat detection technology
            </div>
          </div>
        </motion.div>
      )}
      
      {scanResult && (
        <motion.div 
          className="mt-6"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
        >
          <ProcessMonitor />
        </motion.div>
      )}
    </Layout>
  );
} 