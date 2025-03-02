import React, { useState, useEffect } from 'react';
import Head from 'next/head';
import Layout from '../components/Layout';
import { motion } from 'framer-motion';
import { 
  ShieldExclamationIcon, 
  MagnifyingGlassIcon,
  FunnelIcon,
  ArrowPathIcon,
  ChevronDownIcon,
  EyeIcon,
  TrashIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

type Incident = {
  id: string;
  timestamp: string;
  source: string;
  status: 'pending' | 'analyzed' | 'resolved' | 'false_positive';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  details: {
    subject?: string;
    sender?: string;
    urls?: number;
    score: number;
  };
};

export default function IncidentsPage() {
  const [isLoading, setIsLoading] = useState(true);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [filter, setFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  
  // Simulate data loading
  useEffect(() => {
    const timer = setTimeout(() => {
      // Mock incidents data
      const mockIncidents: Incident[] = [
        {
          id: 'INC-001',
          timestamp: '2023-03-01T14:32:00Z',
          source: 'Email',
          status: 'analyzed',
          risk_level: 'critical',
          details: {
            subject: 'Urgent: Your account has been compromised',
            sender: 'security@suspicious-bank.com',
            urls: 3,
            score: 92
          }
        },
        {
          id: 'INC-002',
          timestamp: '2023-03-01T12:15:00Z',
          source: 'Email',
          status: 'resolved',
          risk_level: 'high',
          details: {
            subject: 'Your package delivery notification',
            sender: 'delivery@fake-shipping.com',
            urls: 2,
            score: 85
          }
        },
        {
          id: 'INC-003',
          timestamp: '2023-03-01T10:45:00Z',
          source: 'Web',
          status: 'pending',
          risk_level: 'medium',
          details: {
            subject: 'Login attempt from new device',
            sender: 'no-reply@company-portal.com',
            urls: 1,
            score: 65
          }
        },
        {
          id: 'INC-004',
          timestamp: '2023-02-28T16:20:00Z',
          source: 'Email',
          status: 'false_positive',
          risk_level: 'low',
          details: {
            subject: 'Team meeting reminder',
            sender: 'calendar@company.com',
            urls: 0,
            score: 25
          }
        },
        {
          id: 'INC-005',
          timestamp: '2023-02-28T09:10:00Z',
          source: 'Email',
          status: 'analyzed',
          risk_level: 'high',
          details: {
            subject: 'Invoice payment overdue',
            sender: 'billing@fake-vendor.com',
            urls: 2,
            score: 88
          }
        },
      ];
      
      setIncidents(mockIncidents);
      setIsLoading(false);
    }, 1500);
    
    return () => clearTimeout(timer);
  }, []);
  
  // Filter incidents based on selected filter and search query
  const filteredIncidents = incidents.filter(incident => {
    // Apply status filter
    if (filter !== 'all' && incident.status !== filter) {
      return false;
    }
    
    // Apply search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        incident.id.toLowerCase().includes(query) ||
        incident.details.subject?.toLowerCase().includes(query) ||
        incident.details.sender?.toLowerCase().includes(query)
      );
    }
    
    return true;
  });
  
  const getRiskLevelBadge = (level: Incident['risk_level']) => {
    switch (level) {
      case 'critical':
        return <span className="px-2 py-1 text-xs font-medium rounded-full bg-danger-100 text-danger-800 dark:bg-danger-900/50 dark:text-danger-100">Critical</span>;
      case 'high':
        return <span className="px-2 py-1 text-xs font-medium rounded-full bg-danger-100 text-danger-800 dark:bg-danger-900/50 dark:text-danger-100">High</span>;
      case 'medium':
        return <span className="px-2 py-1 text-xs font-medium rounded-full bg-warning-100 text-warning-800 dark:bg-warning-900/50 dark:text-warning-100">Medium</span>;
      case 'low':
        return <span className="px-2 py-1 text-xs font-medium rounded-full bg-success-100 text-success-800 dark:bg-success-900/50 dark:text-success-100">Low</span>;
      default:
        return null;
    }
  };
  
  const getStatusIcon = (status: Incident['status']) => {
    switch (status) {
      case 'analyzed':
        return <ExclamationTriangleIcon className="w-5 h-5 text-warning-500" />;
      case 'resolved':
        return <CheckCircleIcon className="w-5 h-5 text-success-500" />;
      case 'false_positive':
        return <XCircleIcon className="w-5 h-5 text-gray-500" />;
      case 'pending':
      default:
        return <div className="w-5 h-5 rounded-full border-2 border-gray-300 border-t-primary-500 animate-spin"></div>;
    }
  };
  
  return (
    <Layout>
      <Head>
        <title>PhishGuard - Incidents</title>
        <meta name="description" content="Phishing incidents detected by the system" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      
      <div className="mb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Incidents</h1>
          <p className="text-gray-500 dark:text-gray-400">
            Phishing incidents detected by the system
          </p>
        </div>
        
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative">
            <input
              type="text"
              placeholder="Search incidents..."
              className="pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-700 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 dark:bg-gray-800"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
          </div>
          
          <div className="flex gap-3">
            <div className="relative">
              <button className="px-4 py-2 bg-white dark:bg-gray-800 rounded-md shadow-sm border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center">
                <FunnelIcon className="w-5 h-5 mr-2" />
                Filter
                <ChevronDownIcon className="w-4 h-4 ml-2" />
              </button>
              
              {/* Filter dropdown would go here */}
            </div>
            
            <motion.button 
              className="px-4 py-2 bg-white dark:bg-gray-800 rounded-md shadow-sm border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors flex items-center"
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
            >
              <ArrowPathIcon className="w-5 h-5 mr-2" />
              Refresh
            </motion.button>
          </div>
        </div>
      </div>
      
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex space-x-4">
            <button 
              className={`px-3 py-1 rounded-md ${filter === 'all' ? 'bg-primary-100 dark:bg-primary-900/50 text-primary-800 dark:text-primary-100' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}`}
              onClick={() => setFilter('all')}
            >
              All
            </button>
            <button 
              className={`px-3 py-1 rounded-md ${filter === 'pending' ? 'bg-primary-100 dark:bg-primary-900/50 text-primary-800 dark:text-primary-100' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}`}
              onClick={() => setFilter('pending')}
            >
              Pending
            </button>
            <button 
              className={`px-3 py-1 rounded-md ${filter === 'analyzed' ? 'bg-primary-100 dark:bg-primary-900/50 text-primary-800 dark:text-primary-100' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}`}
              onClick={() => setFilter('analyzed')}
            >
              Analyzed
            </button>
            <button 
              className={`px-3 py-1 rounded-md ${filter === 'resolved' ? 'bg-primary-100 dark:bg-primary-900/50 text-primary-800 dark:text-primary-100' : 'hover:bg-gray-100 dark:hover:bg-gray-700'}`}
              onClick={() => setFilter('resolved')}
            >
              Resolved
            </button>
          </div>
          
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Showing {filteredIncidents.length} of {incidents.length} incidents
          </div>
        </div>
        
        {isLoading ? (
          <div className="p-8 flex flex-col items-center justify-center">
            <div className="w-16 h-16 border-4 border-gray-200 border-t-primary-500 rounded-full animate-spin mb-4"></div>
            <p className="text-gray-500 dark:text-gray-400">Loading incidents...</p>
          </div>
        ) : filteredIncidents.length === 0 ? (
          <div className="p-8 flex flex-col items-center justify-center">
            <div className="w-16 h-16 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center mb-4">
              <ShieldExclamationIcon className="w-8 h-8 text-gray-400" />
            </div>
            <h3 className="text-xl font-semibold mb-2">No incidents found</h3>
            <p className="text-gray-500 dark:text-gray-400 text-center max-w-md">
              {searchQuery 
                ? `No incidents match your search query "${searchQuery}"`
                : 'No incidents match the selected filter'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700 text-left">
                <tr>
                  <th className="px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">ID</th>
                  <th className="px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Timestamp</th>
                  <th className="px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Source</th>
                  <th className="px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Subject</th>
                  <th className="px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Risk Level</th>
                  <th className="px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {filteredIncidents.map((incident, index) => (
                  <motion.tr 
                    key={incident.id}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                  >
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="font-medium">{incident.id}</span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {new Date(incident.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {incident.source}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col">
                        <span className="font-medium truncate max-w-xs">{incident.details.subject}</span>
                        <span className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">{incident.details.sender}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getRiskLevelBadge(incident.risk_level)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(incident.status)}
                        <span className="ml-2 capitalize">{incident.status.replace('_', ' ')}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex space-x-2">
                        <button className="p-1 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 hover:text-primary-500">
                          <EyeIcon className="w-5 h-5" />
                        </button>
                        <button className="p-1 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500 hover:text-danger-500">
                          <TrashIcon className="w-5 h-5" />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        
        <div className="p-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Showing page 1 of 1
          </div>
          
          <div className="flex space-x-2">
            <button className="px-3 py-1 rounded-md bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-50" disabled>
              Previous
            </button>
            <button className="px-3 py-1 rounded-md bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 disabled:opacity-50" disabled>
              Next
            </button>
          </div>
        </div>
      </div>
    </Layout>
  );
} 