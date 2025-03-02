import React, { useState } from 'react';
import Head from 'next/head';
import Layout from '../components/Layout';
import { motion } from 'framer-motion';
import {
  DocumentTextIcon,
  ArrowDownTrayIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  ChevronDownIcon,
  LinkIcon,
  EnvelopeIcon,
  ShieldExclamationIcon,
  ClockIcon,
  CalendarIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  FolderIcon,
  EyeIcon,
  PrinterIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';

// Type definitions for report data
type EmailDetails = {
  subject: string;
  attachments: number;
  linkedDomains: string[];
  ipOrigin: string;
  country: string;
  techniques: string[];
};

type UrlDetails = {
  domainAge: string;
  sslValid: boolean;
  redirectChain: number;
  ipOrigin: string;
  country: string;
  techniques: string[];
};

type Report = {
  id: string;
  date: string;
  type: 'email' | 'url';
  target: string;
  threat: string;
  source: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'blocked' | 'quarantined' | 'flagged' | 'allowed';
  details: EmailDetails | UrlDetails;
};

// Mock data for reports
const mockReports: Report[] = [
  {
    id: 'RPT-8742',
    date: '2023-09-12 14:32:21',
    type: 'email',
    target: 'john.smith@company.com',
    threat: 'Credential Phishing',
    source: 'phishing-attempt@suspicious-domain.net',
    severity: 'high',
    status: 'blocked',
    details: {
      subject: 'Urgent: Your account needs verification',
      attachments: 2,
      linkedDomains: ['account-verify-now.com'],
      ipOrigin: '103.45.78.122',
      country: 'Russia',
      techniques: ['Brand Impersonation', 'Urgency Tactics', 'Malicious Attachment']
    }
  },
  {
    id: 'RPT-8741',
    date: '2023-09-12 13:15:47',
    type: 'url',
    target: 'https://login-secure-verify.info/account/restore',
    threat: 'Fake Login Page',
    source: 'SMS Link',
    severity: 'high',
    status: 'blocked',
    details: {
      domainAge: '3 days',
      sslValid: false,
      redirectChain: 2,
      ipOrigin: '91.234.67.12',
      country: 'Ukraine',
      techniques: ['URL Manipulation', 'Brand Impersonation', 'Typosquatting']
    }
  },
  {
    id: 'RPT-8739',
    date: '2023-09-12 10:22:05',
    type: 'email',
    target: 'finance@company.com',
    threat: 'Business Email Compromise',
    source: 'ceo-urgent@mail-secure-notify.com',
    severity: 'critical',
    status: 'blocked',
    details: {
      subject: 'Urgent wire transfer needed',
      attachments: 1,
      linkedDomains: ['secure-docs-view.net'],
      ipOrigin: '45.67.23.89',
      country: 'Nigeria',
      techniques: ['CEO Impersonation', 'Urgency Tactics', 'Wire Transfer Request']
    }
  },
  {
    id: 'RPT-8736',
    date: '2023-09-11 16:40:12',
    type: 'url',
    target: 'https://cloud-document-share.com/financial/invoice_08923.pdf',
    threat: 'Malware Distribution',
    source: 'Email Link',
    severity: 'medium',
    status: 'blocked',
    details: {
      domainAge: '15 days',
      sslValid: true,
      redirectChain: 1,
      ipOrigin: '187.23.45.112',
      country: 'Brazil',
      techniques: ['Fake Document Download', 'Malware Distribution']
    }
  },
  {
    id: 'RPT-8734',
    date: '2023-09-11 14:12:37',
    type: 'email',
    target: 'hr@company.com',
    threat: 'Spear Phishing',
    source: 'resume-application@gmail.com',
    severity: 'medium',
    status: 'quarantined',
    details: {
      subject: 'Application for Senior Position',
      attachments: 1,
      linkedDomains: [],
      ipOrigin: '78.45.67.23',
      country: 'United States',
      techniques: ['Targeted Attack', 'Malicious Attachment', 'Social Engineering']
    }
  },
  {
    id: 'RPT-8731',
    date: '2023-09-11 09:05:23',
    type: 'url',
    target: 'https://microsoft365-login-verify.com/secure',
    threat: 'Credential Phishing',
    source: 'Email Link',
    severity: 'high',
    status: 'blocked',
    details: {
      domainAge: '1 day',
      sslValid: true,
      redirectChain: 3,
      ipOrigin: '103.45.22.89',
      country: 'China',
      techniques: ['Brand Impersonation', 'Look-alike Domain', 'Credential Harvesting']
    }
  },
  {
    id: 'RPT-8729',
    date: '2023-09-10 22:14:56',
    type: 'email',
    target: 'support@company.com',
    threat: 'Spam Campaign',
    source: 'marketing@special-offers-now.com',
    severity: 'low',
    status: 'flagged',
    details: {
      subject: 'SPECIAL DISCOUNT FOR YOU!!!',
      attachments: 0,
      linkedDomains: ['special-offers-now.com'],
      ipOrigin: '209.85.167.43',
      country: 'United States',
      techniques: ['Mass Mailing', 'Misleading Subject']
    }
  }
];

export default function ReportsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [dateRange, setDateRange] = useState('all');
  const [expandedReportId, setExpandedReportId] = useState<string | null>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  // Handle report generation
  const handleGenerateReport = (format: 'pdf' | 'csv' | 'xlsx') => {
    setIsGeneratingReport(true);
    
    // Simulate report generation
    setTimeout(() => {
      setIsGeneratingReport(false);
      // In a real implementation, this would trigger a download
      alert(`Report downloaded in ${format.toUpperCase()} format`);
    }, 1500);
  };

  // Apply filters to reports
  const filteredReports = mockReports.filter(report => {
    // Search term filter
    if (searchTerm && 
        !report.id.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !report.target.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !report.threat.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }
    
    // Type filter
    if (typeFilter !== 'all' && report.type !== typeFilter) {
      return false;
    }
    
    // Severity filter
    if (severityFilter !== 'all' && report.severity !== severityFilter) {
      return false;
    }
    
    // Status filter
    if (statusFilter !== 'all' && report.status !== statusFilter) {
      return false;
    }
    
    // Date range filter would be implemented here in a real application
    
    return true;
  });

  // Get severity badge styles
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-danger-100 text-danger-800 dark:bg-danger-900/40 dark:text-danger-200';
      case 'high':
        return 'bg-danger-100/70 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300';
      case 'medium':
        return 'bg-warning-100 text-warning-800 dark:bg-warning-900/30 dark:text-warning-300';
      case 'low':
        return 'bg-success-100 text-success-800 dark:bg-success-900/30 dark:text-success-300';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300';
    }
  };

  // Get status badge styles and icon
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'blocked':
        return {
          className: 'bg-success-100 text-success-800 dark:bg-success-900/30 dark:text-success-300',
          icon: <CheckCircleIcon className="w-3 h-3 mr-1" />
        };
      case 'quarantined':
        return {
          className: 'bg-warning-100 text-warning-800 dark:bg-warning-900/30 dark:text-warning-300',
          icon: <ExclamationTriangleIcon className="w-3 h-3 mr-1" />
        };
      case 'flagged':
        return {
          className: 'bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-300',
          icon: <FolderIcon className="w-3 h-3 mr-1" />
        };
      case 'allowed':
        return {
          className: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300',
          icon: <XCircleIcon className="w-3 h-3 mr-1" />
        };
      default:
        return {
          className: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300',
          icon: null
        };
    }
  };

  // Type guard functions to check the type of report details
  const isEmailDetails = (details: EmailDetails | UrlDetails): details is EmailDetails => {
    return 'subject' in details;
  };

  const isUrlDetails = (details: EmailDetails | UrlDetails): details is UrlDetails => {
    return 'domainAge' in details;
  };

  return (
    <Layout>
      <Head>
        <title>Phishing Reports | PhishGuard</title>
        <meta name="description" content="View and analyze detailed phishing detection reports" />
      </Head>

      <div className="mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Phishing Reports</h1>
          <p className="text-gray-500 dark:text-gray-400">
            View and analyze detailed threat detection reports
          </p>
        </div>

        <div className="flex space-x-2">
          <motion.button
            className="px-3 py-2 bg-primary-500 text-white rounded-lg hover:bg-primary-600 transition-colors flex items-center shadow-sm"
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            onClick={() => handleGenerateReport('pdf')}
            disabled={isGeneratingReport}
          >
            {isGeneratingReport ? (
              <>
                <ArrowPathIcon className="w-4 h-4 mr-2 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
                Export Report
              </>
            )}
          </motion.button>
          
          <motion.button
            className="p-2 border border-gray-300/80 dark:border-gray-600/80 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/70 transition-colors"
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            aria-label="Print report"
          >
            <PrinterIcon className="w-5 h-5" />
          </motion.button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-4 border border-gray-200/70 dark:border-gray-700/70 mb-6">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                <MagnifyingGlassIcon className="w-5 h-5 text-gray-400" />
              </div>
              <input
                type="search"
                className="w-full p-2.5 pl-10 text-sm border border-gray-300/80 dark:border-gray-600/80 rounded-lg focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700/70 dark:placeholder-gray-400"
                placeholder="Search reports by ID, target or threat type..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
          
          <div className="flex flex-wrap gap-2">
            <select
              className="p-2.5 text-sm border border-gray-300/80 dark:border-gray-600/80 rounded-lg focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700/70"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
            >
              <option value="all">All Types</option>
              <option value="email">Email</option>
              <option value="url">URL</option>
            </select>
            
            <select
              className="p-2.5 text-sm border border-gray-300/80 dark:border-gray-600/80 rounded-lg focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700/70"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            
            <select
              className="p-2.5 text-sm border border-gray-300/80 dark:border-gray-600/80 rounded-lg focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700/70"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="all">All Statuses</option>
              <option value="blocked">Blocked</option>
              <option value="quarantined">Quarantined</option>
              <option value="flagged">Flagged</option>
              <option value="allowed">Allowed</option>
            </select>
            
            <select
              className="p-2.5 text-sm border border-gray-300/80 dark:border-gray-600/80 rounded-lg focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700/70"
              value={dateRange}
              onChange={(e) => setDateRange(e.target.value)}
            >
              <option value="all">All Dates</option>
              <option value="today">Today</option>
              <option value="yesterday">Yesterday</option>
              <option value="week">This Week</option>
              <option value="month">This Month</option>
              <option value="custom">Custom Range</option>
            </select>
            
            <button
              className="p-2.5 text-sm bg-gray-100 dark:bg-gray-700 border border-gray-300/80 dark:border-gray-600/80 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 flex items-center text-gray-700 dark:text-gray-300"
              onClick={() => {
                setSearchTerm('');
                setTypeFilter('all');
                setSeverityFilter('all');
                setStatusFilter('all');
                setDateRange('all');
              }}
            >
              <FunnelIcon className="w-4 h-4 mr-1" />
              Reset Filters
            </button>
          </div>
        </div>
      </div>

      {/* Reports List */}
      <div className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md border border-gray-200/70 dark:border-gray-700/70 overflow-hidden">
        {filteredReports.length === 0 ? (
          <div className="p-8 text-center">
            <DocumentTextIcon className="w-12 h-12 mx-auto text-gray-400 mb-3" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-1">No reports found</h3>
            <p className="text-gray-500 dark:text-gray-400">Try adjusting your search or filter criteria</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50/80 dark:bg-gray-700/80">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Report ID
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Date & Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Target
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Threat
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {filteredReports.map((report) => {
                  const isExpanded = expandedReportId === report.id;
                  const statusBadge = getStatusBadge(report.status);
                  
                  return (
                    <React.Fragment key={report.id}>
                      <tr className="hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors">
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          {report.id}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                          <div className="flex items-center">
                            <ClockIcon className="w-4 h-4 mr-1.5" />
                            {report.date}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <div className="flex items-center">
                            {report.type === 'email' ? (
                              <EnvelopeIcon className="w-4 h-4 mr-1.5 text-primary-500" />
                            ) : (
                              <LinkIcon className="w-4 h-4 mr-1.5 text-primary-500" />
                            )}
                            {report.type === 'email' ? 'Email' : 'URL'}
                          </div>
                        </td>
                        <td className="px-6 py-4 text-sm max-w-xs truncate">
                          {report.target}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <div className="flex items-center">
                            <ShieldExclamationIcon className="w-4 h-4 mr-1.5 text-warning-500" />
                            {report.threat}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex px-2 py-1 rounded-full text-xs font-medium ${getSeverityBadge(report.severity)}`}>
                            {report.severity.charAt(0).toUpperCase() + report.severity.slice(1)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${statusBadge.className}`}>
                            {statusBadge.icon}
                            {report.status.charAt(0).toUpperCase() + report.status.slice(1)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                          <button
                            className="text-primary-600 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300 inline-flex items-center"
                            onClick={() => setExpandedReportId(isExpanded ? null : report.id)}
                          >
                            <EyeIcon className="w-4 h-4 mr-1" />
                            {isExpanded ? 'Hide Details' : 'View Details'}
                          </button>
                        </td>
                      </tr>
                      
                      {/* Expanded details panel */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={8} className="px-6 py-4 bg-gray-50/80 dark:bg-gray-750/80">
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: 'auto' }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.3 }}
                              className="text-sm"
                            >
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="space-y-4">
                                  <h4 className="font-medium">Threat Details</h4>
                                  
                                  {/* Email specific details */}
                                  {report.type === 'email' && isEmailDetails(report.details) && (
                                    <>
                                      <div>
                                        <p className="text-gray-500 dark:text-gray-400 mb-1">Subject</p>
                                        <p className="font-medium">{report.details.subject}</p>
                                      </div>
                                      <div>
                                        <p className="text-gray-500 dark:text-gray-400 mb-1">Source</p>
                                        <p className="font-medium">{report.source}</p>
                                      </div>
                                      <div>
                                        <p className="text-gray-500 dark:text-gray-400 mb-1">Attachments</p>
                                        <p className="font-medium">{report.details.attachments}</p>
                                      </div>
                                    </>
                                  )}
                                  
                                  {/* URL specific details */}
                                  {report.type === 'url' && isUrlDetails(report.details) && (
                                    <>
                                      <div>
                                        <p className="text-gray-500 dark:text-gray-400 mb-1">Domain Age</p>
                                        <p className="font-medium">{report.details.domainAge}</p>
                                      </div>
                                      <div>
                                        <p className="text-gray-500 dark:text-gray-400 mb-1">SSL Certificate</p>
                                        <p className="font-medium">
                                          {report.details.sslValid ? (
                                            <span className="text-success-500">Valid</span>
                                          ) : (
                                            <span className="text-danger-500">Invalid/Missing</span>
                                          )}
                                        </p>
                                      </div>
                                      <div>
                                        <p className="text-gray-500 dark:text-gray-400 mb-1">Redirect Chain</p>
                                        <p className="font-medium">{report.details.redirectChain} redirect(s)</p>
                                      </div>
                                    </>
                                  )}
                                </div>
                                
                                <div className="space-y-4">
                                  <h4 className="font-medium">Threat Sources</h4>
                                  <div>
                                    <p className="text-gray-500 dark:text-gray-400 mb-1">IP Origin</p>
                                    <p className="font-medium flex items-center">
                                      {report.details.ipOrigin} 
                                      <span className="ml-2 text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">
                                        {report.details.country}
                                      </span>
                                    </p>
                                  </div>
                                  
                                  {/* Linked domains for email reports */}
                                  {report.type === 'email' && isEmailDetails(report.details) && report.details.linkedDomains.length > 0 && (
                                    <div>
                                      <p className="text-gray-500 dark:text-gray-400 mb-1">Linked Domains</p>
                                      <ul className="list-disc list-inside pl-2">
                                        {report.details.linkedDomains.map((domain, index) => (
                                          <li key={index} className="font-medium">{domain}</li>
                                        ))}
                                      </ul>
                                    </div>
                                  )}
                                  
                                  <div>
                                    <p className="text-gray-500 dark:text-gray-400 mb-1">Attack Techniques</p>
                                    <div className="flex flex-wrap gap-2">
                                      {report.details.techniques.map((technique, index) => (
                                        <span 
                                          key={index}
                                          className="text-xs px-2 py-1 bg-primary-100 dark:bg-primary-900/30 text-primary-800 dark:text-primary-300 rounded-full"
                                        >
                                          {technique}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              </div>
                              
                              <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-700 flex justify-between">
                                <button className="text-primary-600 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300 inline-flex items-center text-sm">
                                  <ArrowDownTrayIcon className="w-4 h-4 mr-1" />
                                  Download Full Report
                                </button>
                                <button className="text-danger-600 hover:text-danger-900 dark:text-danger-400 dark:hover:text-danger-300 inline-flex items-center text-sm">
                                  <XCircleIcon className="w-4 h-4 mr-1" />
                                  Delete Report
                                </button>
                              </div>
                            </motion.div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        
        {/* Pagination (simplified) */}
        <div className="bg-gray-50/80 dark:bg-gray-750/80 px-6 py-3 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Showing <span className="font-medium">{filteredReports.length}</span> of <span className="font-medium">{mockReports.length}</span> reports
          </div>
          
          <div className="flex items-center space-x-2">
            <button className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-sm disabled:opacity-50 disabled:cursor-not-allowed">
              Previous
            </button>
            <button className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md bg-primary-500 text-white text-sm">
              1
            </button>
            <button className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-sm">
              2
            </button>
            <button className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-sm">
              Next
            </button>
          </div>
        </div>
      </div>
    </Layout>
  );
} 