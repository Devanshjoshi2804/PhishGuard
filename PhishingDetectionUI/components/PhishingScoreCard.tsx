import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

type PhishingScoreCardProps = {
  score: number;
  details?: {
    category: string;
    score: number;
    description: string;
  }[];
  isLoading?: boolean;
};

const PhishingScoreCard = ({ 
  score, 
  details = [], 
  isLoading = false 
}: PhishingScoreCardProps) => {
  const [animatedScore, setAnimatedScore] = useState(0);
  
  // Determine color based on score
  const getScoreColor = (value: number) => {
    if (value < 30) return 'text-success-500';
    if (value < 70) return 'text-warning-500';
    return 'text-danger-500';
  };
  
  const getScoreBgColor = (value: number) => {
    if (value < 30) return 'bg-success-500';
    if (value < 70) return 'bg-warning-500';
    return 'bg-danger-500';
  };
  
  const getScoreLabel = (value: number) => {
    if (value < 30) return 'Low Risk';
    if (value < 70) return 'Medium Risk';
    return 'High Risk';
  };
  
  // Animate score on mount
  useEffect(() => {
    if (isLoading) return;
    
    const interval = setInterval(() => {
      setAnimatedScore(prev => {
        if (prev >= score) {
          clearInterval(interval);
          return score;
        }
        return prev + 1;
      });
    }, 20);
    
    return () => clearInterval(interval);
  }, [score, isLoading]);
  
  if (isLoading) {
    return (
      <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70 animate-pulse">
        <div className="flex flex-col items-center mb-6">
          <div className="w-32 h-32 rounded-full bg-gray-200 dark:bg-gray-700 mb-4"></div>
          <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-24 mb-2"></div>
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-16"></div>
        </div>
        <div className="space-y-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="flex justify-between items-center">
              <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/3"></div>
              <div className="w-full max-w-xs">
                <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded"></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }
  
  return (
    <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70">
      <div className="flex flex-col items-center mb-6">
        <div className="relative mb-4">
          {/* Background glow effect */}
          <motion.div 
            className={`absolute inset-0 rounded-full blur-lg ${getScoreBgColor(score).replace('bg-', 'bg-')}/30 z-0`}
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
          
          <svg className="w-32 h-32 relative z-10" viewBox="0 0 100 100">
            {/* Background circle */}
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke="currentColor"
              className="text-gray-200 dark:text-gray-700"
              strokeWidth="8"
            />
            
            {/* Score circle */}
            <motion.circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke={getScoreBgColor(score)}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={`${animatedScore * 2.83} 283`}
              strokeDashoffset="0"
              transform="rotate(-90 50 50)"
              initial={{ strokeDasharray: "0 283" }}
              animate={{ strokeDasharray: `${score * 2.83} 283` }}
              transition={{ duration: 1.5, ease: "easeOut" }}
            />
            
            {/* Shine effect */}
            <motion.circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke="white"
              strokeWidth="2"
              strokeOpacity="0.5"
              strokeDasharray="10 30"
              initial={{ strokeDashoffset: 0 }}
              animate={{ strokeDashoffset: 200 }}
              transition={{ 
                duration: 20, 
                repeat: Infinity,
                repeatType: "loop",
                ease: "linear"
              }}
            />
          </svg>
          
          <div className="absolute inset-0 flex flex-col items-center justify-center z-20">
            <span className={`text-4xl font-bold ${getScoreColor(score)}`}>
              {animatedScore}
            </span>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {getScoreLabel(score)}
            </span>
          </div>
        </div>
        
        <h3 className="text-xl font-semibold mb-1">Phishing Risk Score</h3>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Real-time threat assessment
        </p>
      </div>
      
      {details.length > 0 && (
        <div className="space-y-4">
          {details.map((detail, index) => (
            <motion.div 
              key={detail.category}
              className="flex justify-between items-center"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <span className="text-sm font-medium">{detail.category}</span>
              <div className="w-full max-w-xs ml-4">
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <motion.div 
                    className={`${getScoreBgColor(detail.score)} relative`}
                    style={{ width: `${detail.score}%`, height: '100%' }}
                    initial={{ width: 0 }}
                    animate={{ width: `${detail.score}%` }}
                    transition={{ duration: 0.8, delay: 0.5 + (index * 0.1) }}
                  >
                    {/* Animated gradient overlay for shine effect */}
                    <motion.div 
                      className="absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-30"
                      initial={{ left: "-100%" }}
                      animate={{ left: "100%" }}
                      transition={{ 
                        duration: 1.5, 
                        repeat: Infinity,
                        repeatDelay: 1,
                        ease: "easeInOut"
                      }}
                    />
                  </motion.div>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  {detail.description}
                </p>
              </div>
            </motion.div>
          ))}
        </div>
      )}
      
      <div className="mt-6 pt-4 border-t border-gray-200/70 dark:border-gray-700/70">
        <div className="flex justify-between items-center text-xs text-gray-500 dark:text-gray-400">
          <span>Last updated: Just now</span>
          <motion.button 
            className="text-primary-500 hover:text-primary-600 font-medium flex items-center"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh
          </motion.button>
        </div>
      </div>
    </div>
  );
};

export default PhishingScoreCard; 