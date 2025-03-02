import React, { useState } from 'react';
import Head from 'next/head';
import Layout from '../components/Layout';
import { motion } from 'framer-motion';
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  ArrowUpIcon,
  ArrowDownIcon,
  ClockIcon,
  MapPinIcon,
  GlobeAltIcon,
  ShieldExclamationIcon
} from '@heroicons/react/24/outline';

// Mock data for the charts and analytics
const mockThreatData = {
  totalThreats: 243,
  threatsBlocked: 238,
  threatsTrending: 12.4,
  threatsByType: [
    { type: 'Phishing', count: 142, percentage: 58.4, trend: 'up' },
    { type: 'Malware', count: 47, percentage: 19.3, trend: 'down' },
    { type: 'Social Engineering', count: 32, percentage: 13.2, trend: 'up' },
    { type: 'Credential Theft', count: 22, percentage: 9.1, trend: 'stable' }
  ],
  topPhishingDomains: [
    { domain: 'security-alert-account.com', count: 23, severity: 'high' },
    { domain: 'login-verify-secure.net', count: 18, severity: 'high' },
    { domain: 'account-update-required.info', count: 14, severity: 'high' },
    { domain: 'document-share.security-docs.com', count: 11, severity: 'medium' },
    { domain: 'banking-alert.financial-verify.com', count: 9, severity: 'medium' }
  ],
  weeklyStats: [
    { day: 'Mon', count: 28 },
    { day: 'Tue', count: 42 },
    { day: 'Wed', count: 35 },
    { day: 'Thu', count: 27 },
    { day: 'Fri', count: 43 },
    { day: 'Sat', count: 21 },
    { day: 'Sun', count: 18 }
  ],
  geographicData: [
    { country: 'United States', count: 87, percentage: 35.8 },
    { country: 'Russia', count: 42, percentage: 17.3 },
    { country: 'China', count: 38, percentage: 15.6 },
    { country: 'Nigeria', count: 27, percentage: 11.1 },
    { country: 'Other', count: 49, percentage: 20.2 }
  ]
};

export default function AnalysisPage() {
  const [timeRange, setTimeRange] = useState('7d');
  const [focusedStat, setFocusedStat] = useState<string | null>(null);

  const handleTimeRangeChange = (range: string) => {
    setTimeRange(range);
    // In a real implementation, this would trigger a data refresh
  };

  // Calculate the max value for the weekly chart
  const maxWeeklyValue = Math.max(...mockThreatData.weeklyStats.map(day => day.count));

  return (
    <Layout>
      <Head>
        <title>Threat Analysis | PhishGuard</title>
        <meta name="description" content="Advanced threat analysis and phishing detection insights" />
      </Head>

      <div className="mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">Threat Analysis</h1>
          <p className="text-gray-500 dark:text-gray-400">
            Comprehensive insights into phishing and security threats
          </p>
        </div>

        <div className="flex items-center space-x-2 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm rounded-lg p-1 shadow-sm border border-gray-200/70 dark:border-gray-700/70">
          {['24h', '7d', '30d', '90d'].map(range => (
            <button
              key={range}
              className={`px-3 py-1.5 text-sm rounded-md ${
                timeRange === range
                  ? 'bg-primary-500 text-white'
                  : 'hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
              onClick={() => handleTimeRangeChange(range)}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        {/* Summary Stats Cards */}
        <motion.div
          className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70"
          whileHover={{ y: -5, transition: { duration: 0.2 } }}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <div className="flex items-start justify-between">
            <div>
              <p className="text-gray-500 dark:text-gray-400 text-sm">Total Threats Detected</p>
              <h3 className="text-3xl font-bold mt-1">{mockThreatData.totalThreats}</h3>
            </div>
            <div className="p-3 bg-primary-100/50 dark:bg-primary-900/30 rounded-lg">
              <ShieldExclamationIcon className="w-6 h-6 text-primary-500" />
            </div>
          </div>
          <div className="flex items-center mt-4 text-sm">
            <ArrowUpIcon className="w-4 h-4 text-danger-500 mr-1" />
            <span className="text-danger-500 font-medium">{mockThreatData.threatsTrending}%</span>
            <span className="text-gray-500 dark:text-gray-400 ml-1">vs previous period</span>
          </div>
        </motion.div>

        <motion.div
          className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70"
          whileHover={{ y: -5, transition: { duration: 0.2 } }}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
        >
          <div className="flex items-start justify-between">
            <div>
              <p className="text-gray-500 dark:text-gray-400 text-sm">Threats Blocked</p>
              <h3 className="text-3xl font-bold mt-1">{mockThreatData.threatsBlocked}</h3>
            </div>
            <div className="p-3 bg-success-100/50 dark:bg-success-900/30 rounded-lg">
              <ShieldCheckIcon className="w-6 h-6 text-success-500" />
            </div>
          </div>
          <div className="flex items-center mt-4 text-sm">
            <span className="text-success-500 font-medium">{((mockThreatData.threatsBlocked / mockThreatData.totalThreats) * 100).toFixed(1)}%</span>
            <span className="text-gray-500 dark:text-gray-400 ml-1">block rate</span>
          </div>
        </motion.div>

        <motion.div
          className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70"
          whileHover={{ y: -5, transition: { duration: 0.2 } }}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
        >
          <div className="flex items-start justify-between">
            <div>
              <p className="text-gray-500 dark:text-gray-400 text-sm">Last Threat</p>
              <h3 className="text-lg font-bold mt-1">login-verify-secure.net</h3>
            </div>
            <div className="p-3 bg-warning-100/50 dark:bg-warning-900/30 rounded-lg">
              <ClockIcon className="w-6 h-6 text-warning-500" />
            </div>
          </div>
          <div className="flex items-center mt-4 text-sm">
            <span className="text-gray-500 dark:text-gray-400">17 minutes ago</span>
            <span className="bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300 text-xs px-2 py-0.5 rounded-full ml-2">High Severity</span>
          </div>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Weekly Trends Chart */}
        <motion.div
          className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70 lg:col-span-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
        >
          <div className="flex items-center justify-between mb-6">
            <h3 className="font-bold flex items-center">
              <ChartBarIcon className="w-5 h-5 mr-2 text-primary-500" />
              Weekly Threat Activity
            </h3>
          </div>

          <div className="h-64 flex items-end justify-between">
            {mockThreatData.weeklyStats.map((day, index) => {
              const height = (day.count / maxWeeklyValue) * 100;
              return (
                <div key={day.day} className="flex flex-col items-center flex-1">
                  <motion.div
                    className="w-full mx-1 rounded-t-md bg-primary-500/80 dark:bg-primary-500/70 relative group"
                    style={{ height: `${height}%` }}
                    initial={{ height: 0 }}
                    animate={{ height: `${height}%` }}
                    transition={{ duration: 0.5, delay: 0.1 * index }}
                    onMouseEnter={() => setFocusedStat(day.day)}
                    onMouseLeave={() => setFocusedStat(null)}
                  >
                    <div className={`absolute -top-10 left-1/2 transform -translate-x-1/2 bg-gray-800 text-white px-2 py-1 rounded text-xs whitespace-nowrap ${
                      focusedStat === day.day ? 'opacity-100' : 'opacity-0'
                    } transition-opacity duration-200`}>
                      {day.count} threats
                    </div>
                  </motion.div>
                  <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">{day.day}</div>
                </div>
              );
            })}
          </div>
        </motion.div>

        {/* Threat Distribution */}
        <motion.div
          className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.4 }}
        >
          <h3 className="font-bold flex items-center mb-6">
            <ExclamationTriangleIcon className="w-5 h-5 mr-2 text-primary-500" />
            Threat Distribution
          </h3>

          <div className="space-y-4">
            {mockThreatData.threatsByType.map((threat, index) => (
              <div key={threat.type}>
                <div className="flex items-center justify-between text-sm mb-1">
                  <span className="font-medium">{threat.type}</span>
                  <div className="flex items-center">
                    <span>{threat.percentage}%</span>
                    {threat.trend === 'up' && (
                      <ArrowUpIcon className="w-3 h-3 ml-1 text-danger-500" />
                    )}
                    {threat.trend === 'down' && (
                      <ArrowDownIcon className="w-3 h-3 ml-1 text-success-500" />
                    )}
                  </div>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 overflow-hidden">
                  <motion.div
                    className="h-full rounded-full bg-primary-500"
                    style={{ width: `${threat.percentage}%` }}
                    initial={{ width: 0 }}
                    animate={{ width: `${threat.percentage}%` }}
                    transition={{ duration: 0.5, delay: 0.1 * index }}
                  />
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Phishing Domains */}
        <motion.div
          className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.5 }}
        >
          <h3 className="font-bold flex items-center mb-4">
            <GlobeAltIcon className="w-5 h-5 mr-2 text-primary-500" />
            Top Phishing Domains
          </h3>

          <div className="overflow-hidden">
            <table className="min-w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="pb-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Domain</th>
                  <th className="pb-2 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Hits</th>
                  <th className="pb-2 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {mockThreatData.topPhishingDomains.map((domain, index) => (
                  <motion.tr 
                    key={domain.domain}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3, delay: 0.1 * index }}
                    className="hover:bg-gray-50 dark:hover:bg-gray-750"
                  >
                    <td className="py-3 text-sm truncate max-w-[240px]">{domain.domain}</td>
                    <td className="py-3 text-sm text-right">{domain.count}</td>
                    <td className="py-3 text-sm text-right">
                      <span className={`inline-flex px-2 py-0.5 rounded-full text-xs ${
                        domain.severity === 'high' 
                          ? 'bg-danger-100 text-danger-800 dark:bg-danger-900/30 dark:text-danger-300' 
                          : 'bg-warning-100 text-warning-800 dark:bg-warning-900/30 dark:text-warning-300'
                      }`}>
                        {domain.severity}
                      </span>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* Geographic Distribution */}
        <motion.div
          className="bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm rounded-xl shadow-md p-6 border border-gray-200/70 dark:border-gray-700/70"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.6 }}
        >
          <h3 className="font-bold flex items-center mb-4">
            <MapPinIcon className="w-5 h-5 mr-2 text-primary-500" />
            Geographic Origins
          </h3>

          <div className="space-y-3">
            {mockThreatData.geographicData.map((country, index) => (
              <motion.div 
                key={country.country}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: 0.1 * index }}
                className="flex items-center"
              >
                <div className="w-32 font-medium text-sm">{country.country}</div>
                <div className="flex-1">
                  <div className="relative">
                    <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                      <motion.div 
                        className="h-full bg-primary-500/70 rounded-full"
                        style={{ width: `${country.percentage}%` }}
                        initial={{ width: 0 }}
                        animate={{ width: `${country.percentage}%` }}
                        transition={{ duration: 0.5, delay: 0.1 * index }}
                      />
                    </div>
                    <span className="absolute right-0 top-1/2 transform -translate-y-1/2 -translate-x-1 text-xs font-medium">
                      {country.percentage}%
                    </span>
                  </div>
                </div>
                <div className="w-12 text-right text-sm">{country.count}</div>
              </motion.div>
            ))}
          </div>

          <div className="mt-4 text-xs text-gray-500 dark:text-gray-400 border-t border-gray-200 dark:border-gray-700 pt-3">
            <p>Data based on IP geolocation and threat intelligence</p>
          </div>
        </motion.div>
      </div>
    </Layout>
  );
} 