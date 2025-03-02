import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  ShieldCheckIcon, 
  ShieldExclamationIcon, 
  ClockIcon, 
  ChartBarIcon 
} from '@heroicons/react/24/outline';

type StatCardProps = {
  title: string;
  value: number;
  icon: React.ReactNode;
  color: string;
  delay?: number;
};

const StatCard = ({ title, value, icon, color, delay = 0 }: StatCardProps) => {
  const [displayValue, setDisplayValue] = useState(0);
  
  useEffect(() => {
    const timer = setTimeout(() => {
      const interval = setInterval(() => {
        setDisplayValue(prev => {
          if (prev >= value) {
            clearInterval(interval);
            return value;
          }
          return prev + Math.ceil(value / 20);
        });
      }, 50);
      
      return () => clearInterval(interval);
    }, delay);
    
    return () => clearTimeout(timer);
  }, [value, delay]);
  
  return (
    <motion.div 
      className={`bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 border-l-4 ${color}`}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: delay / 1000 }}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</p>
          <h3 className="text-3xl font-bold mt-1">{displayValue.toLocaleString()}</h3>
        </div>
        <div className={`p-3 rounded-full ${color.replace('border-', 'bg-').replace('-500', '-100')} ${color.replace('border-', 'text-')}`}>
          {icon}
        </div>
      </div>
    </motion.div>
  );
};

type DashboardStatsProps = {
  stats?: {
    totalScanned: number;
    phishingDetected: number;
    pendingAnalysis: number;
    riskScore: number;
  };
  isLoading?: boolean;
};

const DashboardStats = ({ 
  stats = {
    totalScanned: 1254,
    phishingDetected: 87,
    pendingAnalysis: 12,
    riskScore: 24
  }, 
  isLoading = false 
}: DashboardStatsProps) => {
  
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 animate-pulse">
            <div className="flex items-center justify-between">
              <div className="w-full">
                <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/3 mb-2"></div>
                <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
              </div>
              <div className="w-12 h-12 bg-gray-200 dark:bg-gray-700 rounded-full"></div>
            </div>
          </div>
        ))}
      </div>
    );
  }
  
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <StatCard 
        title="Total Emails Scanned" 
        value={stats.totalScanned} 
        icon={<ChartBarIcon className="w-6 h-6" />} 
        color="border-primary-500" 
        delay={0}
      />
      <StatCard 
        title="Phishing Detected" 
        value={stats.phishingDetected} 
        icon={<ShieldExclamationIcon className="w-6 h-6" />} 
        color="border-danger-500" 
        delay={200}
      />
      <StatCard 
        title="Pending Analysis" 
        value={stats.pendingAnalysis} 
        icon={<ClockIcon className="w-6 h-6" />} 
        color="border-warning-500" 
        delay={400}
      />
      <StatCard 
        title="Average Risk Score" 
        value={stats.riskScore} 
        icon={<ShieldCheckIcon className="w-6 h-6" />} 
        color="border-success-500" 
        delay={600}
      />
    </div>
  );
};

export default DashboardStats; 