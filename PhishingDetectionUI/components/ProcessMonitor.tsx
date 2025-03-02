import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ClockIcon, 
  CheckCircleIcon, 
  ExclamationCircleIcon, 
  ArrowPathIcon,
  DocumentMagnifyingGlassIcon,
  LockClosedIcon,
  ShieldCheckIcon,
  GlobeAltIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

type ProcessStep = {
  id: string;
  name: string;
  status: 'idle' | 'active' | 'completed' | 'error';
  type: 'ingestion' | 'analysis' | 'intelligence' | 'decision' | 'monitoring';
  lastActivity?: string;
  details?: string;
  progress?: number; // 0-100
};

type ProcessMonitorProps = {
  processes?: ProcessStep[];
  isLoading?: boolean;
  onProcessClick?: (process: ProcessStep) => void;
};

// Rename component from AgentActivityMonitor to ProcessMonitor
const ProcessMonitor = ({ 
  processes = [], 
  isLoading = false,
  onProcessClick
}: ProcessMonitorProps) => {
  const [activeProcesses, setActiveProcesses] = useState<ProcessStep[]>([]);
  
  // Simulate process activity if no real data is provided
  useEffect(() => {
    if (processes.length > 0 || isLoading) return;
    
    const simulatedProcesses: ProcessStep[] = [
      { id: '1', name: 'Email Parsing', status: 'completed', type: 'ingestion', lastActivity: '2 min ago', progress: 100 },
      { id: '2', name: 'Content Analysis', status: 'active', type: 'analysis', lastActivity: 'Just now', progress: 65 },
      { id: '3', name: 'URL Verification', status: 'active', type: 'analysis', lastActivity: 'Just now', progress: 45 },
      { id: '4', name: 'Threat Lookup', status: 'idle', type: 'intelligence', lastActivity: 'Waiting...', progress: 0 },
      { id: '5', name: 'Pattern Detection', status: 'idle', type: 'analysis', lastActivity: 'Waiting...', progress: 0 },
      { id: '6', name: 'Risk Assessment', status: 'idle', type: 'decision', lastActivity: 'Waiting...', progress: 0 },
    ];
    
    setActiveProcesses(simulatedProcesses);
    
    // Simulate changing process statuses
    const interval = setInterval(() => {
      setActiveProcesses(prev => {
        return prev.map(process => {
          // Update progress for active processes
          if (process.status === 'active') {
            const newProgress = Math.min(100, (process.progress || 0) + Math.floor(Math.random() * 15));
            const newStatus = newProgress >= 100 ? 'completed' : 'active';
            return { 
              ...process, 
              progress: newProgress, 
              status: newStatus,
              lastActivity: newStatus === 'completed' ? 'Just now' : process.lastActivity 
            };
          }
          
          // Start idle processes
          if (process.status === 'idle' && Math.random() > 0.8) {
            return { 
              ...process, 
              status: 'active', 
              lastActivity: 'Just now',
              progress: Math.floor(Math.random() * 20)
            };
          }
          
          return process;
        });
      });
    }, 2000);
    
    return () => clearInterval(interval);
  }, [processes, isLoading]);
  
  const getProcessTypeColor = (type: ProcessStep['type']) => {
    switch (type) {
      case 'ingestion': return 'bg-primary-500 dark:bg-primary-600';
      case 'analysis': return 'bg-purple-500 dark:bg-purple-600';
      case 'intelligence': return 'bg-indigo-500 dark:bg-indigo-600';
      case 'decision': return 'bg-amber-500 dark:bg-amber-600';
      case 'monitoring': return 'bg-emerald-500 dark:bg-emerald-600';
      default: return 'bg-gray-500 dark:bg-gray-600';
    }
  };
  
  const getStatusColor = (status: ProcessStep['status']) => {
    switch (status) {
      case 'active': return 'bg-green-500 dark:bg-green-400';
      case 'completed': return 'bg-blue-500 dark:bg-blue-400';
      case 'error': return 'bg-red-500 dark:bg-red-400';
      default: return 'bg-gray-400 dark:bg-gray-500';
    }
  };
  
  const getStatusIcon = (status: ProcessStep['status'], type: ProcessStep['type']) => {
    if (status === 'active') return <ArrowPathIcon className="w-4 h-4 text-green-500 dark:text-green-400 animate-spin" />;
    if (status === 'completed') return <CheckCircleIcon className="w-4 h-4 text-blue-500 dark:text-blue-400" />;
    if (status === 'error') return <ExclamationCircleIcon className="w-4 h-4 text-red-500 dark:text-red-400" />;
    return <ClockIcon className="w-4 h-4 text-gray-400 dark:text-gray-500" />;
  };
  
  const getProcessIcon = (type: ProcessStep['type']) => {
    switch (type) {
      case 'ingestion': return <DocumentTextIcon className="w-4 h-4" />;
      case 'analysis': return <DocumentMagnifyingGlassIcon className="w-4 h-4" />;
      case 'intelligence': return <GlobeAltIcon className="w-4 h-4" />;
      case 'decision': return <ShieldCheckIcon className="w-4 h-4" />;
      case 'monitoring': return <LockClosedIcon className="w-4 h-4" />;
      default: return null;
    }
  };
  
  const displayProcesses = processes.length > 0 ? processes : activeProcesses;
  
  if (isLoading) {
    return (
      <div className="bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm rounded-xl shadow-lg p-6 border border-gray-100 dark:border-gray-700">
        <h3 className="text-xl font-semibold mb-4 text-gray-800 dark:text-white">Analysis Pipeline</h3>
        <div className="space-y-4 animate-pulse">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="flex items-center p-3 border border-gray-200 dark:border-gray-700 rounded-lg bg-white/30 dark:bg-gray-700/30">
              <div className="w-3 h-3 rounded-full bg-gray-200 dark:bg-gray-600 mr-3"></div>
              <div className="flex-1">
                <div className="h-4 bg-gray-200 dark:bg-gray-600 rounded w-1/4 mb-2"></div>
                <div className="h-3 bg-gray-200 dark:bg-gray-600 rounded w-1/3"></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }
  
  return (
    <div className="bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm rounded-xl shadow-lg p-6 border border-gray-100 dark:border-gray-700">
      <h3 className="text-xl font-semibold mb-4 text-gray-800 dark:text-white">Analysis Pipeline</h3>
      
      <div className="space-y-3">
        <AnimatePresence>
          {displayProcesses.map(process => (
            <motion.div 
              key={process.id}
              className="flex items-center p-3 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-white dark:hover:bg-gray-700 cursor-pointer transition-all duration-300 bg-white/50 dark:bg-gray-800/50"
              onClick={() => onProcessClick && onProcessClick(process)}
              whileHover={{ x: 5, boxShadow: "0 4px 6px rgba(0, 0, 0, 0.05)" }}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.3 }}
            >
              <div className="relative mr-3 flex items-center justify-center w-8 h-8 rounded-full bg-gray-100 dark:bg-gray-700">
                {getProcessIcon(process.type)}
              </div>
              
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium text-gray-800 dark:text-white">{process.name}</h4>
                  <span className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                    {getStatusIcon(process.status, process.type)}
                    {process.lastActivity}
                  </span>
                </div>
                
                {process.status === 'active' && typeof process.progress === 'number' && (
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 mt-2">
                    <motion.div 
                      className="h-1.5 rounded-full bg-primary-500 dark:bg-primary-400"
                      initial={{ width: 0 }}
                      animate={{ width: `${process.progress}%` }}
                      transition={{ duration: 0.5 }}
                    />
                  </div>
                )}
                
                <div className="flex items-center mt-1">
                  <span className="text-xs text-gray-500 dark:text-gray-400 capitalize">
                    {process.status} {process.details && `- ${process.details}`}
                  </span>
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
      
      <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400">
          <span>Process Types:</span>
          <div className="flex flex-wrap gap-3">
            <div className="flex items-center">
              <span className="inline-block w-2 h-2 rounded-full bg-primary-500 mr-1"></span>
              <span>Input</span>
            </div>
            <div className="flex items-center">
              <span className="inline-block w-2 h-2 rounded-full bg-purple-500 mr-1"></span>
              <span>Analysis</span>
            </div>
            <div className="flex items-center">
              <span className="inline-block w-2 h-2 rounded-full bg-indigo-500 mr-1"></span>
              <span>Intelligence</span>
            </div>
            <div className="flex items-center">
              <span className="inline-block w-2 h-2 rounded-full bg-amber-500 mr-1"></span>
              <span>Evaluation</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProcessMonitor; 