import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { 
  ShieldCheckIcon, 
  EnvelopeIcon, 
  ArrowPathIcon,
  ExclamationTriangleIcon,
  DocumentTextIcon,
  LinkIcon,
  LockClosedIcon,
  CheckBadgeIcon
} from '@heroicons/react/24/outline';

type EmailScannerProps = {
  onScanEmail: (emailContent: string) => Promise<void>;
  isScanning?: boolean;
};

const EmailScanner = ({ onScanEmail, isScanning = false }: EmailScannerProps) => {
  const { register, handleSubmit, formState: { errors }, reset } = useForm();
  const [showAnimation, setShowAnimation] = useState(false);
  const [copied, setCopied] = useState(false);
  
  const onSubmit = async (data: any) => {
    setShowAnimation(true);
    await onScanEmail(data.emailContent);
    setTimeout(() => {
      setShowAnimation(false);
    }, 1000);
  };
  
  const handlePasteExample = () => {
    // Safe email examples
    const safeEmails = [
      `From: support@github.com
Subject: Your GitHub security report for June 2023

Dear Developer,

Your monthly GitHub security scan has been completed.
No security vulnerabilities were detected in your repositories.

You can view the complete report here:
https://github.com/settings/security-report

GitHub Security Team`,

      `From: no-reply@microsoft.com
Subject: Microsoft 365 subscription renewal confirmation

Hello,

Your Microsoft 365 subscription has been successfully renewed.
Your next billing date will be July 15, 2024.

To view your subscription details, please log in to your account at:
https://account.microsoft.com/services

Microsoft Billing Team`,

      `From: aws-marketing@amazon.com
Subject: AWS Security Best Practices Guide

Greetings AWS Customer,

We've published our updated security best practices guide for 2023.
Download the guide to learn about the latest security recommendations.

Read more: https://aws.amazon.com/security/best-practices/

AWS Security Team`
    ];
    
    // Unsafe email examples
    const unsafeEmails = [
      `From: security@banking-alerts.com
Subject: URGENT: Your account has been compromised

Dear Customer,

We have detected suspicious activity on your account.
Please verify your identity immediately by clicking:
http://secure-banking-portal.info/verify

Failure to verify within 24 hours will result in account suspension.

Banking Security Team`,

      `From: paypal-support@secure-alerts.net
Subject: PayPal: Unusual login attempt detected

Dear valued customer,

We noticed an unauthorized login attempt to your PayPal account.
To secure your account, please confirm your information:
https://paypal-account-verify.info/secure

This request will expire in 48 hours.

PayPal Support`,

      `From: apple@id-verification.support
Subject: Your Apple ID has been locked

Your Apple account has been temporarily locked for security reasons.
We detected multiple failed login attempts on your account.

To unlock your account, please verify your information:
http://apple-id-verify.secure-check.com

Apple Support Team`
    ];
    
    // Store the last example type in localStorage
    const lastWasSafe = localStorage.getItem('lastEmailExampleWasSafe') === 'true';
    
    // Get examples based on alternating pattern
    const examples = lastWasSafe ? unsafeEmails : safeEmails;
    
    // Get a random example from the current set
    const selectedExample = examples[Math.floor(Math.random() * examples.length)];
    
    // Update the stored state for next time
    localStorage.setItem('lastEmailExampleWasSafe', (!lastWasSafe).toString());

    // Set value to the textarea
    const textarea = document.getElementById('emailContent') as HTMLTextAreaElement;
    if (textarea) {
      textarea.value = selectedExample;
      // Trigger a change event so react-hook-form registers the change
      const event = new Event('input', { bubbles: true });
      textarea.dispatchEvent(event);
    }
  };
  
  const handleClearForm = () => {
    reset();
  };

  const handleCopyToClipboard = () => {
    const textarea = document.getElementById('emailContent') as HTMLTextAreaElement;
    if (textarea && textarea.value) {
      navigator.clipboard.writeText(textarea.value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };
  
  return (
    <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70 relative overflow-hidden">
      <h2 className="text-2xl font-bold mb-6 flex items-center">
        <EnvelopeIcon className="w-6 h-6 mr-2 text-primary-500" />
        Email Scanner
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
            <div className="relative">
              <motion.div 
                className="w-24 h-24 rounded-full border-4 border-primary-500 border-t-transparent"
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
              />
              <motion.div 
                className="absolute inset-0 flex items-center justify-center"
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: [0.8, 1.2, 0.8], opacity: [0.5, 1, 0.5] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                <ShieldCheckIcon className="w-10 h-10 text-primary-500" />
              </motion.div>
            </div>
            <motion.div 
              className="mt-6 text-white text-xl font-bold"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              Scanning Email...
            </motion.div>
            <motion.div 
              className="mt-2 text-white/70 text-sm max-w-md text-center"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.5 }}
            >
              Analyzing content, links, sender reputation, and security indicators using advanced detection technology
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
      
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <div>
          <div className="flex items-center justify-between mb-2">
            <label htmlFor="emailContent" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Paste Email Content
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
                onClick={handleCopyToClipboard}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                disabled={isScanning}
              >
                {copied ? (
                  <>
                    <CheckBadgeIcon className="w-3 h-3 mr-1" />
                    Copied!
                  </>
                ) : (
                  <>
                    <DocumentTextIcon className="w-3 h-3 mr-1" />
                    Copy
                  </>
                )}
              </motion.button>
            </div>
          </div>
          <div className="relative">
            <textarea
              id="emailContent"
              rows={10}
              className={`w-full px-4 py-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 dark:bg-gray-700/70 dark:border-gray-600 ${
                errors.emailContent ? 'border-danger-500 focus:ring-danger-500' : 'border-gray-300 dark:border-gray-600'
              }`}
              placeholder="Paste the full email content including headers..."
              {...register('emailContent', { required: 'Email content is required' })}
              disabled={isScanning}
            />
            <div className="absolute bottom-3 right-3 text-xs text-gray-400 dark:text-gray-500 pointer-events-none">
              Secure Analysis
            </div>
          </div>
          {errors.emailContent && (
            <motion.p 
              className="mt-1 text-sm text-danger-500 flex items-center"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <ExclamationTriangleIcon className="w-4 h-4 mr-1" />
              {errors.emailContent.message?.toString()}
            </motion.p>
          )}
        </div>
        
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-500 dark:text-gray-400">
            <p className="flex items-center">
              <ShieldCheckIcon className="w-4 h-4 mr-1 text-primary-500" />
              Secure analysis with advanced threat detection
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
                  Scan Email
                </>
              )}
            </motion.button>
          </div>
        </div>
      </form>
      
      <div className="mt-6 pt-6 border-t border-gray-200/70 dark:border-gray-700/70">
        <h3 className="text-lg font-semibold mb-2">How it works</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-gray-50/80 dark:bg-gray-700/50 rounded-lg">
            <div className="w-10 h-10 rounded-full bg-primary-100/80 dark:bg-primary-900/50 flex items-center justify-center mb-3">
              <EnvelopeIcon className="w-6 h-6 text-primary-500" />
            </div>
            <h4 className="font-medium mb-1">1. Content Analysis</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Advanced threat detection evaluates the email structure and content
            </p>
          </div>
          
          <div className="p-4 bg-gray-50/80 dark:bg-gray-700/50 rounded-lg">
            <div className="w-10 h-10 rounded-full bg-primary-100/80 dark:bg-primary-900/50 flex items-center justify-center mb-3">
              <LinkIcon className="w-6 h-6 text-primary-500" />
            </div>
            <h4 className="font-medium mb-1">2. URL & Link Scanning</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Embedded links are checked against known malicious patterns and behavior
            </p>
          </div>
          
          <div className="p-4 bg-gray-50/80 dark:bg-gray-700/50 rounded-lg">
            <div className="w-10 h-10 rounded-full bg-primary-100/80 dark:bg-primary-900/50 flex items-center justify-center mb-3">
              <LockClosedIcon className="w-6 h-6 text-primary-500" />
            </div>
            <h4 className="font-medium mb-1">3. Security Assessment</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Get detailed risk scores and actionable recommendations
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EmailScanner; 