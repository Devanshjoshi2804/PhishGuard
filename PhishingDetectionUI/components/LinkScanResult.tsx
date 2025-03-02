import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  LinkIcon,
  GlobeAltIcon,
  LockClosedIcon,
  LockOpenIcon,
  ClockIcon,
  ServerIcon,
  CodeBracketIcon,
  EyeIcon,
  ArrowTopRightOnSquareIcon,
  XMarkIcon,
  InformationCircleIcon,
  ChevronDownIcon,
  ChevronUpIcon
} from '@heroicons/react/24/outline';

// Type definitions
type ThreatIndicator = {
  name: string;
  value: number;
  status: 'safe' | 'warning' | 'danger';
  description: string;
};

export type LinkAnalysisResult = {
  url: string;
  safetyScore: number; // 0-100
  verdict: 'safe' | 'suspicious' | 'malicious';
  domainInfo: {
    age: number; // in days
    registrar: string;
    expiryDate: string;
    isWhitelisted: boolean;
    previouslyReported: boolean;
  };
  sslInfo: {
    valid: boolean;
    issuer: string;
    expiryDate: string;
    strength: 'weak' | 'medium' | 'strong';
  };
  contentAnalysis: {
    hasMaliciousCode: boolean;
    hasPhishingPatterns: boolean;
    hasSuspiciousForms: boolean;
    redirectCount: number;
  };
  threatIndicators: ThreatIndicator[];
  scanDate: string;
};

type LinkScanResultProps = {
  result: LinkAnalysisResult;
};

const LinkScanResult = ({ result }: LinkScanResultProps) => {
  const [showDetails, setShowDetails] = useState(false);
  const [animatedScore, setAnimatedScore] = useState(0);
  
  useEffect(() => {
    const interval = setInterval(() => {
      setAnimatedScore(prev => {
        if (prev >= result.safetyScore) {
          clearInterval(interval);
          return result.safetyScore;
        }
        return prev + 1;
      });
    }, 20);
    
    return () => clearInterval(interval);
  }, [result.safetyScore]);
  
  const getScoreColor = (score: number) => {
    if (score >= 70) return 'text-success-500';
    if (score >= 40) return 'text-warning-500';
    return 'text-danger-500';
  };
  
  const getScoreBgColor = (score: number) => {
    if (score >= 70) return 'bg-success-500';
    if (score >= 40) return 'bg-warning-500';
    return 'bg-danger-500';
  };
  
  const getStatusIcon = (verdict: 'safe' | 'suspicious' | 'malicious') => {
    switch (verdict) {
      case 'safe':
        return <ShieldCheckIcon className="w-6 h-6 text-success-500" />;
      case 'suspicious':
        return <ShieldExclamationIcon className="w-6 h-6 text-warning-500" />;
      case 'malicious':
        return <ExclamationTriangleIcon className="w-6 h-6 text-danger-500" />;
    }
  };
  
  const getStatusColor = (verdict: 'safe' | 'suspicious' | 'malicious') => {
    switch (verdict) {
      case 'safe': return 'bg-success-100 dark:bg-success-900/30 text-success-800 dark:text-success-200';
      case 'suspicious': return 'bg-warning-100 dark:bg-warning-900/30 text-warning-800 dark:text-warning-200';
      case 'malicious': return 'bg-danger-100 dark:bg-danger-900/30 text-danger-800 dark:text-danger-200';
    }
  };
  
  const getStatusText = (verdict: 'safe' | 'suspicious' | 'malicious') => {
    switch (verdict) {
      case 'safe': return 'Safe';
      case 'suspicious': return 'Suspicious';
      case 'malicious': return 'Malicious';
    }
  };
  
  const getDomainAge = (days: number) => {
    if (days < 30) return { text: `${days} days (Very New)`, status: 'danger' };
    if (days < 180) return { text: `${Math.floor(days / 30)} months (New)`, status: 'warning' };
    if (days < 365) return { text: `${Math.floor(days / 30)} months`, status: 'normal' };
    return { text: `${Math.floor(days / 365)} years`, status: 'good' };
  };
  
  const formatUrl = (url: string) => {
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      return {
        protocol: urlObj.protocol,
        domain: urlObj.hostname,
        path: `${urlObj.pathname}${urlObj.search}${urlObj.hash}`
      };
    } catch (e) {
      return {
        protocol: 'https:',
        domain: url.split('/')[0],
        path: url.includes('/') ? `/${url.split('/').slice(1).join('/')}` : ''
      };
    }
  };
  
  const urlParts = formatUrl(result.url);
  const domainAge = getDomainAge(result.domainInfo.age);
  
  return (
    <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md border border-gray-200/70 dark:border-gray-700/70 overflow-hidden">
      <div className="p-6">
        <div className="flex items-start justify-between mb-4">
          <h3 className="text-xl font-bold flex items-center">
            <LinkIcon className="w-5 h-5 mr-2 text-primary-500" />
            URL Analysis Results
          </h3>
          
          <div className={`flex items-center px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(result.verdict)}`}>
            {getStatusIcon(result.verdict)}
            <span className="ml-1">{getStatusText(result.verdict)}</span>
          </div>
        </div>
        
        <div className="flex flex-col md:flex-row md:items-stretch gap-6 mb-6">
          {/* URL Info */}
          <div className="flex-1">
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">Analyzed URL</h4>
              <div className="flex items-center mb-2 break-all bg-gray-50/80 dark:bg-gray-700/50 p-3 rounded-lg">
                <span className="text-primary-500 mr-1">{urlParts.protocol}//</span>
                <span className="font-medium">{urlParts.domain}</span>
                <span className="text-gray-500 dark:text-gray-400">{urlParts.path}</span>
              </div>
              <div className="flex text-xs space-x-4 text-gray-500 dark:text-gray-400">
                <span className="flex items-center">
                  <ClockIcon className="w-3 h-3 mr-1" />
                  Scanned {result.scanDate}
                </span>
                <a 
                  href={result.url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="flex items-center text-primary-500 hover:text-primary-600"
                >
                  <ArrowTopRightOnSquareIcon className="w-3 h-3 mr-1" />
                  Visit URL
                </a>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div className="bg-gray-50/80 dark:bg-gray-700/50 p-3 rounded-lg">
                <div className="flex items-center mb-1">
                  <GlobeAltIcon className="w-4 h-4 mr-1 text-primary-500" />
                  <h5 className="text-sm font-medium">Domain Age</h5>
                </div>
                <p className={`text-sm ${
                  domainAge.status === 'danger' ? 'text-danger-500' :
                  domainAge.status === 'warning' ? 'text-warning-500' :
                  domainAge.status === 'good' ? 'text-success-500' : ''
                }`}>
                  {domainAge.text}
                </p>
              </div>
              
              <div className="bg-gray-50/80 dark:bg-gray-700/50 p-3 rounded-lg">
                <div className="flex items-center mb-1">
                  {result.sslInfo.valid ? (
                    <LockClosedIcon className="w-4 h-4 mr-1 text-success-500" />
                  ) : (
                    <LockOpenIcon className="w-4 h-4 mr-1 text-danger-500" />
                  )}
                  <h5 className="text-sm font-medium">SSL Certificate</h5>
                </div>
                <p className={`text-sm ${result.sslInfo.valid ? 'text-success-500' : 'text-danger-500'}`}>
                  {result.sslInfo.valid ? 'Valid' : 'Invalid/Missing'} 
                  {result.sslInfo.valid && (
                    <span className="text-gray-500 dark:text-gray-400"> ({result.sslInfo.strength})</span>
                  )}
                </p>
              </div>
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-gray-50/80 dark:bg-gray-700/50 p-3 rounded-lg">
                <div className="flex items-center mb-1">
                  <ServerIcon className="w-4 h-4 mr-1 text-primary-500" />
                  <h5 className="text-sm font-medium">Registrar</h5>
                </div>
                <p className="text-sm break-all">{result.domainInfo.registrar}</p>
              </div>
              
              <div className="bg-gray-50/80 dark:bg-gray-700/50 p-3 rounded-lg">
                <div className="flex items-center mb-1">
                  <CodeBracketIcon className="w-4 h-4 mr-1 text-primary-500" />
                  <h5 className="text-sm font-medium">Content Analysis</h5>
                </div>
                {result.contentAnalysis.hasMaliciousCode || 
                 result.contentAnalysis.hasPhishingPatterns || 
                 result.contentAnalysis.hasSuspiciousForms ? (
                  <p className="text-sm text-danger-500">Suspicious content detected</p>
                ) : (
                  <p className="text-sm text-success-500">No suspicious content</p>
                )}
              </div>
            </div>
          </div>
          
          {/* Safety Score */}
          <div className="md:w-64 flex flex-col items-center justify-center bg-gray-50/80 dark:bg-gray-700/50 p-6 rounded-lg">
            <div className="relative mb-4">
              <motion.div 
                className={`absolute inset-0 rounded-full blur-lg ${getScoreBgColor(result.safetyScore)}/30`}
                animate={{
                  scale: [1, 1.05, 1],
                  opacity: [0.5, 0.8, 0.5]
                }}
                transition={{
                  duration: 3,
                  repeat: Infinity,
                  repeatType: "reverse"
                }}
              />
              
              <svg className="w-40 h-40 relative" viewBox="0 0 100 100">
                {/* Background circle */}
                <circle
                  cx="50"
                  cy="50"
                  r="45"
                  fill="none"
                  stroke="currentColor"
                  className="text-gray-200 dark:text-gray-600"
                  strokeWidth="8"
                />
                
                {/* Score circle */}
                <motion.circle
                  cx="50"
                  cy="50"
                  r="45"
                  fill="none"
                  stroke={getScoreBgColor(result.safetyScore)}
                  strokeWidth="8"
                  strokeLinecap="round"
                  strokeDasharray={`${animatedScore * 2.83} 283`}
                  strokeDashoffset="0"
                  transform="rotate(-90 50 50)"
                  initial={{ strokeDasharray: "0 283" }}
                  animate={{ strokeDasharray: `${result.safetyScore * 2.83} 283` }}
                  transition={{ duration: 1.5, ease: "easeOut" }}
                />
                
                {/* Shine effect */}
                <circle
                  cx="50"
                  cy="50"
                  r="45"
                  fill="none"
                  stroke="white"
                  strokeWidth="2"
                  strokeOpacity="0.5"
                  strokeDasharray="10 30"
                />
              </svg>
              
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-4xl font-bold ${getScoreColor(result.safetyScore)}`}>
                  {animatedScore}
                </span>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  Safety Score
                </span>
              </div>
            </div>
            
            <div className="text-center">
              <h4 className="text-lg font-semibold mb-1">
                {result.safetyScore >= 70 ? 'Safe to Visit' :
                 result.safetyScore >= 40 ? 'Use Caution' :
                 'Potentially Dangerous'}
              </h4>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {result.safetyScore >= 70 ? 'This URL appears to be legitimate and safe' :
                 result.safetyScore >= 40 ? 'This URL has some suspicious elements' :
                 'This URL has multiple high-risk indicators'}
              </p>
            </div>
          </div>
        </div>
        
        <div className="mb-4">
          <button 
            className="flex items-center justify-center w-full py-2 border border-gray-200/70 dark:border-gray-700/70 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors text-sm font-medium"
            onClick={() => setShowDetails(!showDetails)}
          >
            {showDetails ? (
              <>
                <ChevronUpIcon className="w-4 h-4 mr-1" />
                Hide Detailed Analysis
              </>
            ) : (
              <>
                <ChevronDownIcon className="w-4 h-4 mr-1" />
                Show Detailed Analysis
              </>
            )}
          </button>
        </div>
        
        {showDetails && (
          <motion.div 
            className="space-y-4 border-t border-gray-200/70 dark:border-gray-700/70 pt-4"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            transition={{ duration: 0.3 }}
          >
            <h4 className="text-base font-semibold flex items-center">
              <EyeIcon className="w-4 h-4 mr-1 text-primary-500" />
              Detailed Threat Indicators
            </h4>
            
            {result.threatIndicators.map((indicator, index) => (
              <div key={index} className="bg-gray-50/80 dark:bg-gray-700/50 p-3 rounded-lg">
                <div className="flex justify-between mb-2">
                  <h5 className="text-sm font-medium flex items-center">
                    {indicator.status === 'safe' && <ShieldCheckIcon className="w-4 h-4 mr-1 text-success-500" />}
                    {indicator.status === 'warning' && <ShieldExclamationIcon className="w-4 h-4 mr-1 text-warning-500" />}
                    {indicator.status === 'danger' && <ExclamationTriangleIcon className="w-4 h-4 mr-1 text-danger-500" />}
                    {indicator.name}
                  </h5>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${
                    indicator.status === 'safe' ? 'bg-success-100 dark:bg-success-900/30 text-success-600 dark:text-success-300' :
                    indicator.status === 'warning' ? 'bg-warning-100 dark:bg-warning-900/30 text-warning-600 dark:text-warning-300' :
                    'bg-danger-100 dark:bg-danger-900/30 text-danger-600 dark:text-danger-300'
                  }`}>
                    {indicator.status === 'safe' ? 'Safe' :
                     indicator.status === 'warning' ? 'Warning' :
                     'Risk'}
                  </span>
                </div>
                
                <div className="mb-2">
                  <div className="h-2 bg-gray-200 dark:bg-gray-600 rounded-full overflow-hidden">
                    <motion.div 
                      className={`h-full ${
                        indicator.status === 'safe' ? 'bg-success-500' :
                        indicator.status === 'warning' ? 'bg-warning-500' :
                        'bg-danger-500'
                      }`}
                      style={{ width: `${indicator.value}%` }}
                      initial={{ width: 0 }}
                      animate={{ width: `${indicator.value}%` }}
                      transition={{ duration: 0.8 }}
                    />
                  </div>
                </div>
                
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {indicator.description}
                </p>
              </div>
            ))}
            
            <div className="flex items-center py-2 px-3 bg-primary-50/70 dark:bg-primary-900/20 rounded-lg text-sm text-primary-600 dark:text-primary-300">
              <InformationCircleIcon className="w-5 h-5 mr-2 flex-shrink-0" />
              <p>This detailed analysis is based on multiple security databases, heuristic analysis, and machine learning algorithms that evaluate URLs for potential threats.</p>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default LinkScanResult; 