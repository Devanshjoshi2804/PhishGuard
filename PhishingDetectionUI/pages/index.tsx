import React, { useState, useEffect, useCallback } from 'react';
import Head from 'next/head';
import Layout from '../components/Layout';
import DashboardStats from '../components/DashboardStats';
import PhishingScoreCard from '../components/PhishingScoreCard';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldCheckIcon, 
  ChartBarIcon,
  ArrowTrendingUpIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
  CheckBadgeIcon,
  ClockIcon,
  BoltIcon
} from '@heroicons/react/24/outline';

// Mock data for phishing score details
const mockScoreDetails = [
  { category: 'Content Analysis', score: 65, description: 'Suspicious language patterns detected' },
  { category: 'URL Security', score: 85, description: 'Malicious links found' },
  { category: 'Domain Verification', score: 70, description: 'Domain has suspicious history' },
  { category: 'Sender Reputation', score: 40, description: 'Sender has mixed reputation' },
];

export default function Home() {
  const [isLoading, setIsLoading] = useState(true);
  const [stats, setStats] = useState({
    totalScanned: 0,
    phishingDetected: 0,
    pendingAnalysis: 0,
    riskScore: 0
  });
  const [recentThreats, setRecentThreats] = useState<any[]>([]);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [systemStatus, setSystemStatus] = useState('operational');
  const [accuracy, setAccuracy] = useState(98.7);
  
  const fetchData = useCallback(async () => {
    setIsLoading(true);
    
    try {
      // In a real implementation, these would be actual API calls
      // const statsResponse = await fetch('/api/stats');
      // const stats = await statsResponse.json();
      // const threatsResponse = await fetch('/api/recent-threats');
      // const threats = await threatsResponse.json();
      
      // Simulate API response delay
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Simulate varying data for demo purposes
      const randomTotal = 1200 + Math.floor(Math.random() * 200);
      const randomDetected = 80 + Math.floor(Math.random() * 15);
      const randomPending = 5 + Math.floor(Math.random() * 10);
      const randomScore = 20 + Math.floor(Math.random() * 10);
      
      setStats({
        totalScanned: randomTotal,
        phishingDetected: randomDetected,
        pendingAnalysis: randomPending,
        riskScore: randomScore
      });
      
      // Simulate recent threats
      const threatTypes = ['Phishing', 'Malware', 'Spoofing', 'Ransomware', 'Data Theft'];
      const sources = ['Email', 'URL', 'Domain', 'Attachment', 'Form'];
      
      const newThreats = Array(4).fill(null).map((_, i) => {
        const type = threatTypes[Math.floor(Math.random() * threatTypes.length)];
        const source = sources[Math.floor(Math.random() * sources.length)];
        const score = 70 + Math.floor(Math.random() * 30);
        
        let time;
        if (i === 0) time = 'Just now';
        else if (i === 1) time = Math.floor(Math.random() * 60) + ' min ago';
        else if (i === 2) time = Math.floor(Math.random() * 5) + ' hours ago';
        else time = Math.floor(Math.random() * 2) + ' days ago';
        
        return { type, source, score, time };
      });
      
      setRecentThreats(newThreats);
      
      // Random accuracy fluctuation for realism
      setAccuracy(98.2 + (Math.random() * 1.2));
      
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);
  
  // Initial data fetch
  useEffect(() => {
    fetchData();
    
    // Set up polling for real-time updates
    const intervalId = setInterval(() => {
      setRefreshTrigger(prev => prev + 1);
    }, 60000); // Update every minute
    
    return () => clearInterval(intervalId);
  }, [fetchData]);
  
  // Refresh when triggered
  useEffect(() => {
    if (refreshTrigger > 0) {
      fetchData();
    }
  }, [refreshTrigger, fetchData]);

  const handleRefresh = () => {
    setRefreshTrigger(prev => prev + 1);
  };
  
  return (
    <Layout>
      <Head>
        <title>PhishGuard - Dashboard</title>
        <meta name="description" content="Real-time Phishing Detection System Dashboard" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      
      <div className="mb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-gray-500 dark:text-gray-400">
            Real-time overview of your phishing detection system
          </p>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="flex items-center space-x-2 px-3 py-1.5 bg-white dark:bg-gray-800/70 rounded-lg shadow-sm border border-gray-200/50 dark:border-gray-700/50 text-sm">
            <div className={`w-2 h-2 rounded-full ${
              systemStatus === 'operational' ? 'bg-success-500 animate-pulse' :
              systemStatus === 'degraded' ? 'bg-warning-500 animate-pulse' :
              'bg-danger-500 animate-pulse'
            }`}></div>
            <span className="font-medium">
              {systemStatus === 'operational' ? 'System Operational' :
               systemStatus === 'degraded' ? 'Performance Degraded' :
               'System Issues Detected'}
            </span>
          </div>
          
          <motion.button 
            className="flex items-center px-4 py-2 bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-lg shadow-sm border border-gray-200/70 dark:border-gray-700/70 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/70 transition-colors"
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            onClick={handleRefresh}
          >
            <ArrowPathIcon className={`w-5 h-5 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            {isLoading ? 'Refreshing...' : 'Refresh Data'}
          </motion.button>
        </div>
      </div>
      
      <div className="mb-8">
        <DashboardStats stats={stats} isLoading={isLoading} />
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="lg:col-span-2">
          <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold flex items-center">
                <ChartBarIcon className="w-5 h-5 mr-2 text-primary-500" />
                Phishing Activity
              </h2>
              
              <div className="flex space-x-2">
                <button className="px-3 py-1 text-sm bg-gray-100/80 dark:bg-gray-700/80 rounded-md hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors">
                  Day
                </button>
                <button className="px-3 py-1 text-sm bg-primary-100/80 dark:bg-primary-900/50 text-primary-800 dark:text-primary-100 rounded-md">
                  Week
                </button>
                <button className="px-3 py-1 text-sm bg-gray-100/80 dark:bg-gray-700/80 rounded-md hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors">
                  Month
                </button>
              </div>
            </div>
            
            {isLoading ? (
              <div className="h-64 flex items-center justify-center">
                <div className="flex flex-col items-center">
                  <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500 mb-3"></div>
                  <p className="text-gray-500 dark:text-gray-400">Loading activity data...</p>
                </div>
              </div>
            ) : (
              <div className="h-64 cyber-grid relative rounded-lg overflow-hidden border border-gray-200/30 dark:border-gray-700/30">
                {/* This would be replaced with a real chart component */}
                <div className="absolute inset-0 flex items-center justify-center">
                  <p className="text-gray-500 dark:text-gray-400">
                    Activity chart would be displayed here
                  </p>
                </div>
              </div>
            )}
            
            <div className="mt-6 pt-6 border-t border-gray-200/70 dark:border-gray-700/70 grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-center">
                <div className="w-10 h-10 rounded-full bg-primary-100/80 dark:bg-primary-900/30 flex items-center justify-center mr-3">
                  <ShieldCheckIcon className="w-6 h-6 text-primary-500" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Detection Rate</p>
                  <p className="text-xl font-bold">94.8%</p>
                </div>
              </div>
              
              <div className="flex items-center">
                <div className="w-10 h-10 rounded-full bg-success-100/80 dark:bg-success-900/30 flex items-center justify-center mr-3">
                  <ArrowTrendingUpIcon className="w-6 h-6 text-success-500" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Accuracy</p>
                  <p className="text-xl font-bold">{accuracy.toFixed(1)}%</p>
                </div>
              </div>
              
              <div className="flex items-center">
                <div className="w-10 h-10 rounded-full bg-warning-100/80 dark:bg-warning-900/30 flex items-center justify-center mr-3">
                  <BoltIcon className="w-6 h-6 text-warning-500" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Avg. Response</p>
                  <p className="text-xl font-bold">1.2s</p>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div>
          <PhishingScoreCard 
            score={75} 
            details={mockScoreDetails} 
            isLoading={isLoading} 
          />
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70">
            <h3 className="text-xl font-semibold mb-6 flex items-center">
              <ClockIcon className="w-5 h-5 mr-2 text-primary-500" />
              System Activity
            </h3>
            
            {isLoading ? (
              <div className="space-y-4 animate-pulse">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="flex items-center p-3 border border-gray-200/70 dark:border-gray-700/70 rounded-lg">
                    <div className="w-3 h-3 rounded-full bg-gray-200 dark:bg-gray-700 mr-3"></div>
                    <div className="flex-1">
                      <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4 mb-2"></div>
                      <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/3"></div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-3">
                {[
                  { activity: 'System scan completed', status: 'completed', time: '3 min ago', details: '145 endpoints scanned' },
                  { activity: 'Threat database updated', status: 'completed', time: '15 min ago', details: '2,450 new signatures added' },
                  { activity: 'Email analysis complete', status: 'completed', time: '28 min ago', details: 'High-risk phishing detected' },
                  { activity: 'System health check', status: 'active', time: 'in progress', details: 'Verifying all components' },
                  { activity: 'Routine maintenance', status: 'scheduled', time: 'in 2 hours', details: 'System optimization' }
                ].map((activity, index) => (
                  <motion.div 
                    key={index}
                    className="flex items-center p-3 border border-gray-200/70 dark:border-gray-700/70 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                  >
                    <div className="relative mr-3">
                      <div className="h-10 w-0.5 rounded-full bg-gray-200 dark:bg-gray-700 opacity-30"></div>
                      <motion.div 
                        className={`absolute top-1/2 -translate-y-1/2 -translate-x-1/2 w-3 h-3 rounded-full ${
                          activity.status === 'completed' ? 'bg-success-500' : 
                          activity.status === 'active' ? 'bg-primary-500' :
                          'bg-gray-400'
                        }`}
                        animate={activity.status === 'active' ? {
                          scale: [1, 1.2, 1],
                          opacity: [0.7, 1, 0.7]
                        } : {}}
                        transition={{ 
                          duration: 2, 
                          repeat: activity.status === 'active' ? Infinity : 0,
                          repeatType: "loop" 
                        }}
                      ></motion.div>
                    </div>
                    
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium">{activity.activity}</h4>
                        <span className="text-xs text-gray-500 dark:text-gray-400">{activity.time}</span>
                      </div>
                      
                      <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        {activity.details}
                      </p>
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </div>
        </div>
        
        <div>
          <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70">
            <h3 className="text-xl font-semibold mb-4 flex items-center">
              <ExclamationTriangleIcon className="w-5 h-5 mr-2 text-warning-500" />
              Recent Threats
            </h3>
            
            {isLoading ? (
              <div className="space-y-4 animate-pulse">
                {[...Array(4)].map((_, i) => (
                  <div key={i} className="flex items-center p-3 border border-gray-200/70 dark:border-gray-700/70 rounded-lg">
                    <div className="w-10 h-10 rounded-full bg-gray-200 dark:bg-gray-700 mr-3"></div>
                    <div className="flex-1">
                      <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4 mb-2"></div>
                      <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-3">
                <AnimatePresence>
                  {recentThreats.map((threat, index) => (
                    <motion.div 
                      key={threat.type + index}
                      className="flex items-center p-3 border border-gray-200/70 dark:border-gray-700/70 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                      whileHover={{ x: 5 }}
                    >
                      <div className={`w-10 h-10 rounded-full flex items-center justify-center mr-3 ${
                        threat.score > 90 
                          ? 'bg-danger-100/80 text-danger-500 dark:bg-danger-900/50 dark:text-danger-400' 
                          : 'bg-warning-100/80 text-warning-500 dark:bg-warning-900/50 dark:text-warning-400'
                      }`}>
                        <span className="font-bold">{threat.score}</span>
                      </div>
                      
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <h4 className="font-medium">{threat.type}</h4>
                          <span className="text-xs text-gray-500 dark:text-gray-400">{threat.time}</span>
                        </div>
                        
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          Source: {threat.source}
                        </p>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>
            )}
            
            <div className="mt-4 pt-4 border-t border-gray-200/70 dark:border-gray-700/70">
              <button className="w-full py-2 text-center text-primary-500 hover:text-primary-600 dark:hover:text-primary-400 font-medium transition-colors">
                View All Threats
              </button>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
} 