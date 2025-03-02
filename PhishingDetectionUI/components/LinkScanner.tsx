import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { 
  ShieldCheckIcon, 
  LinkIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  DocumentTextIcon,
  LockClosedIcon,
  GlobeAltIcon,
  CheckBadgeIcon,
  ServerIcon,
  KeyIcon,
  ShieldExclamationIcon,
  ClockIcon
} from '@heroicons/react/24/outline';

type LinkScannerProps = {
  onScanUrl: (url: string) => Promise<void>;
  isScanning?: boolean;
};

const LinkScanner = ({ onScanUrl, isScanning = false }: LinkScannerProps) => {
  const { register, handleSubmit, formState: { errors }, reset, setValue } = useForm();
  const [showAnimation, setShowAnimation] = useState(false);
  const [copied, setCopied] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStage, setScanStage] = useState('');
  
  const onSubmit = async (data: any) => {
    setShowAnimation(true);
    setScanProgress(0);
    setScanStage('Initializing scan...');

    // Simulate scanning progress for realistic effect
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 100) {
          clearInterval(progressInterval);
          return 100;
        }
        
        // Update scan stage based on progress
        if (prev < 20) {
          setScanStage('Checking domain reputation...');
        } else if (prev < 40) {
          setScanStage('Analyzing URL structure...');
        } else if (prev < 60) {
          setScanStage('Validating SSL certificates...');
        } else if (prev < 80) {
          setScanStage('Cross-referencing with threat database...');
        } else {
          setScanStage('Finalizing security assessment...');
        }
        
        return prev + Math.floor(Math.random() * 5) + 1;
      });
    }, 200);

    await onScanUrl(data.url);
    
    // Ensure we reach 100% before closing animation
    setScanProgress(100);
    setScanStage('Scan complete!');
    
    setTimeout(() => {
      clearInterval(progressInterval);
      setShowAnimation(false);
    }, 1000);
  };
  
  const handlePasteExample = () => {
    // Safe examples
    const safeExamples = [
      'https://github.com/security-resources/documentation',
      'https://developer.mozilla.org/en-US/docs/Web/Security',
      'https://www.cloudflare.com/learning/security/glossary/what-is-encryption/',
      'https://aws.amazon.com/security/?nc1=h_ls',
      'https://www.microsoft.com/en-us/security/business'
    ];
    
    // Unsafe examples
    const unsafeExamples = [
      'http://banking-secure-verification.com/login?id=12345',
      'https://account-security-alert.info/verify-now',
      'https://docs-important-share.com/financial/statement.pdf',
      'http://apple-id-confirm.security-check.net/verify',
      'https://netflix-billing-issue.account-update.info'
    ];
    
    // Store the last example type in localStorage
    const lastWasSafe = localStorage.getItem('lastUrlExampleWasSafe') === 'true';
    
    // Get examples based on alternating pattern
    const examples = lastWasSafe ? unsafeExamples : safeExamples;
    
    // Get a random example from the current set
    const selectedExample = examples[Math.floor(Math.random() * examples.length)];
    
    // Update the stored state for next time
    localStorage.setItem('lastUrlExampleWasSafe', (!lastWasSafe).toString());
    
    setValue('url', selectedExample);
  };
  
  const handleClearForm = () => {
    reset();
  };

  const handlePasteFromClipboard = async () => {
    try {
      const clipboardText = await navigator.clipboard.readText();
      if (clipboardText && clipboardText.includes('http')) {
        setValue('url', clipboardText);
      }
    } catch (error) {
      console.error('Failed to read clipboard:', error);
    }
  };
  
  return (
    <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70 relative overflow-hidden">
      <h2 className="text-2xl font-bold mb-6 flex items-center">
        <LinkIcon className="w-6 h-6 mr-2 text-primary-500" />
        URL Security Scanner
      </h2>
      
      {/* Scanning animation overlay */}
      <AnimatePresence>
        {showAnimation && (
          <motion.div 
            className="absolute inset-0 bg-black/60 backdrop-blur-sm flex flex-col items-center justify-center z-10"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div className="relative w-64 flex flex-col items-center">
              <motion.div 
                className="w-28 h-28 rounded-full border-4 border-primary-500 border-t-transparent relative"
                animate={{ rotate: 360 }}
                transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
              >
                <motion.div 
                  className="absolute inset-0 flex items-center justify-center"
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: [0.8, 1.2, 0.8], opacity: [0.5, 1, 0.5] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  <ShieldCheckIcon className="w-12 h-12 text-primary-500" />
                </motion.div>
              </motion.div>
              
              <div className="w-full mt-8 mb-2">
                <div className="h-2 w-full bg-gray-700 rounded-full overflow-hidden">
                  <motion.div 
                    className="h-full bg-primary-500"
                    style={{ width: `${scanProgress}%` }}
                    initial={{ width: "0%" }}
                  />
                </div>
              </div>
              
              <motion.div 
                className="text-white text-lg font-bold mb-1"
                animate={{ opacity: [0.7, 1, 0.7] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              >
                {scanStage}
              </motion.div>
              
              <motion.div 
                className="text-white/70 text-sm max-w-md text-center"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.5 }}
              >
                <div className="flex items-center justify-center space-x-1 mt-1">
                  <motion.div
                    className="w-2 h-2 bg-primary-400 rounded-full"
                    animate={{ scale: [0.8, 1.2, 0.8] }}
                    transition={{ duration: 1, repeat: Infinity, delay: 0 }}
                  />
                  <motion.div
                    className="w-2 h-2 bg-primary-400 rounded-full"
                    animate={{ scale: [0.8, 1.2, 0.8] }}
                    transition={{ duration: 1, repeat: Infinity, delay: 0.2 }}
                  />
                  <motion.div
                    className="w-2 h-2 bg-primary-400 rounded-full"
                    animate={{ scale: [0.8, 1.2, 0.8] }}
                    transition={{ duration: 1, repeat: Infinity, delay: 0.4 }}
                  />
                </div>
              </motion.div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <div>
          <div className="flex items-center justify-between mb-2">
            <label htmlFor="url" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Enter URL to Scan
            </label>
            <div className="flex items-center space-x-2">
              <motion.button
                type="button"
                className="text-xs text-primary-500 hover:text-primary-600 dark:hover:text-primary-400 flex items-center"
                onClick={handlePasteExample}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                disabled={isScanning}
              >
                <DocumentTextIcon className="w-3 h-3 mr-1" />
                Use Example
              </motion.button>
              <motion.button
                type="button"
                className="text-xs text-primary-500 hover:text-primary-600 dark:hover:text-primary-400 flex items-center"
                onClick={handlePasteFromClipboard}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                disabled={isScanning}
              >
                <DocumentTextIcon className="w-3 h-3 mr-1" />
                Paste from Clipboard
              </motion.button>
            </div>
          </div>
          <div className="relative">
            <input
              id="url"
              type="text"
              className={`w-full px-4 py-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 dark:bg-gray-700/70 dark:border-gray-600 ${
                errors.url ? 'border-danger-500 focus:ring-danger-500' : 'border-gray-300 dark:border-gray-600'
              }`}
              placeholder="https://example.com/path/to/page"
              {...register('url', { 
                required: 'URL is required',
                pattern: {
                  value: /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/,
                  message: "Please enter a valid URL"
                }
              })}
              disabled={isScanning}
            />
            <div className="absolute top-3 right-3 text-xs text-gray-400 dark:text-gray-500 pointer-events-none">
              <LockClosedIcon className="w-4 h-4" />
            </div>
          </div>
          {errors.url && (
            <motion.p 
              className="mt-1 text-sm text-danger-500 flex items-center"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <ExclamationTriangleIcon className="w-4 h-4 mr-1" />
              {errors.url.message?.toString()}
            </motion.p>
          )}
        </div>
        
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-500 dark:text-gray-400">
            <p className="flex items-center">
              <ShieldCheckIcon className="w-4 h-4 mr-1 text-primary-500" />
              Real-time threat intelligence & analysis
            </p>
          </div>
          
          <div className="flex space-x-3">
            <motion.button
              type="button"
              className="px-4 py-2 border border-gray-300/80 dark:border-gray-600/80 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/70 transition-colors"
              onClick={handleClearForm}
              disabled={isScanning}
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
            >
              Clear
            </motion.button>
            
            <motion.button
              type="submit"
              className="px-4 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors flex items-center shadow-md"
              disabled={isScanning}
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
            >
              {isScanning ? (
                <>
                  <ArrowPathIcon className="w-5 h-5 mr-2 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <ShieldCheckIcon className="w-5 h-5 mr-2" />
                  Scan URL
                </>
              )}
            </motion.button>
          </div>
        </div>
      </form>
      
      <div className="mt-6 pt-6 border-t border-gray-200/70 dark:border-gray-700/70">
        <h3 className="text-lg font-semibold mb-4">How URL Scanning Works</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 bg-gray-50/80 dark:bg-gray-700/50 rounded-lg h-full">
            <div className="w-10 h-10 rounded-full bg-primary-100/80 dark:bg-primary-900/50 flex items-center justify-center mb-3">
              <GlobeAltIcon className="w-6 h-6 text-primary-500" />
            </div>
            <h4 className="font-medium mb-1">1. Domain Analysis</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Verifies domain age, reputation, and ownership against known threat databases
            </p>
          </div>
          
          <div className="p-4 bg-gray-50/80 dark:bg-gray-700/50 rounded-lg h-full">
            <div className="w-10 h-10 rounded-full bg-primary-100/80 dark:bg-primary-900/50 flex items-center justify-center mb-3">
              <KeyIcon className="w-6 h-6 text-primary-500" />
            </div>
            <h4 className="font-medium mb-1">2. SSL Verification</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Examines SSL certificate validity, expiration, and cryptographic strength
            </p>
          </div>
          
          <div className="p-4 bg-gray-50/80 dark:bg-gray-700/50 rounded-lg h-full">
            <div className="w-10 h-10 rounded-full bg-primary-100/80 dark:bg-primary-900/50 flex items-center justify-center mb-3">
              <ShieldExclamationIcon className="w-6 h-6 text-primary-500" />
            </div>
            <h4 className="font-medium mb-1">3. Content Inspection</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Analyzes page content for malicious code, phishing patterns, and social engineering tactics
            </p>
          </div>
          
          <div className="p-4 bg-gray-50/80 dark:bg-gray-700/50 rounded-lg h-full">
            <div className="w-10 h-10 rounded-full bg-primary-100/80 dark:bg-primary-900/50 flex items-center justify-center mb-3">
              <ServerIcon className="w-6 h-6 text-primary-500" />
            </div>
            <h4 className="font-medium mb-1">4. Risk Assessment</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Provides comprehensive safety score with detailed breakdown of potential threats
            </p>
          </div>
        </div>
        
        <div className="mt-6">
          <div className="flex items-center mb-2">
            <ClockIcon className="w-4 h-4 text-primary-500 mr-2" />
            <h4 className="text-sm font-medium">Real-time Protection Features</h4>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-gray-500 dark:text-gray-400">
            <div className="flex items-center">
              <CheckBadgeIcon className="w-3 h-3 mr-1 text-success-500" />
              Malware & exploit detection
            </div>
            <div className="flex items-center">
              <CheckBadgeIcon className="w-3 h-3 mr-1 text-success-500" />
              Phishing & social engineering
            </div>
            <div className="flex items-center">
              <CheckBadgeIcon className="w-3 h-3 mr-1 text-success-500" />
              Drive-by download protection
            </div>
            <div className="flex items-center">
              <CheckBadgeIcon className="w-3 h-3 mr-1 text-success-500" />
              Typosquatting identification
            </div>
            <div className="flex items-center">
              <CheckBadgeIcon className="w-3 h-3 mr-1 text-success-500" />
              Malicious redirect detection
            </div>
            <div className="flex items-center">
              <CheckBadgeIcon className="w-3 h-3 mr-1 text-success-500" />
              Browser exploit mitigation
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LinkScanner; 