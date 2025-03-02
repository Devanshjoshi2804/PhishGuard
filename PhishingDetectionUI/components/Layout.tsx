import React, { ReactNode, useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { 
  HomeIcon, 
  ShieldCheckIcon, 
  ChartBarIcon, 
  DocumentTextIcon, 
  CogIcon,
  BellIcon,
  ArrowLeftOnRectangleIcon,
  Bars3Icon,
  XMarkIcon,
  SunIcon,
  MoonIcon,
  LinkIcon
} from '@heroicons/react/24/outline';
import { motion, AnimatePresence } from 'framer-motion';

type NavItemProps = {
  href: string;
  icon: React.ReactNode;
  title: string;
  active?: boolean;
};

const NavItem = ({ href, icon, title, active }: NavItemProps) => {
  return (
    <Link href={href} className={`flex items-center px-4 py-3 mb-2 rounded-xl transition-all duration-300 ${
      active 
        ? 'bg-primary-500/10 text-primary-600 dark:bg-primary-900/20 dark:text-primary-400 backdrop-blur-sm' 
        : 'hover:bg-gray-100/80 dark:hover:bg-gray-800/50 hover:backdrop-blur-sm'
    }`}>
      <div className="w-6 h-6 mr-3">
        {icon}
      </div>
      <span className="font-medium">{title}</span>
      {active && (
        <motion.div 
          className="w-1 h-6 ml-auto bg-primary-500 rounded-full"
          layoutId="activeNavIndicator"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ type: "spring", stiffness: 300, damping: 30 }}
        />
      )}
    </Link>
  );
};

type LayoutProps = {
  children: ReactNode;
};

const Layout = ({ children }: LayoutProps) => {
  const router = useRouter();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [notifications, setNotifications] = useState<{id: string, text: string, time: string}[]>([]);
  const [showNotifications, setShowNotifications] = useState(false);

  useEffect(() => {
    // Check system preference for dark mode
    if (typeof window !== 'undefined') {
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        setDarkMode(true);
        document.documentElement.classList.add('dark');
      }

      // Listen for changes in system preference
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
        setDarkMode(e.matches);
        if (e.matches) {
          document.documentElement.classList.add('dark');
        } else {
          document.documentElement.classList.remove('dark');
        }
      });
    }

    // Fetch some mock notifications
    setNotifications([
      { id: '1', text: 'High-risk phishing detected from finance@company-urgent.com', time: '5 min ago' },
      { id: '2', text: 'System update completed successfully', time: '1 hour ago' },
      { id: '3', text: 'New threat intelligence data integrated', time: '3 hours ago' }
    ]);
  }, []);

  const toggleSidebar = () => setSidebarOpen(!sidebarOpen);
  
  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
    if (darkMode) {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  };

  return (
    <div className="flex h-screen bg-gray-50/95 dark:bg-gray-900/95 text-gray-900 dark:text-gray-100 overflow-hidden">
      {/* Mobile sidebar backdrop */}
      <AnimatePresence>
        {sidebarOpen && (
          <motion.div 
            className="fixed inset-0 z-20 bg-black/20 backdrop-blur-sm lg:hidden"
            onClick={toggleSidebar}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <motion.aside 
        className={`fixed inset-y-0 left-0 z-30 w-64 bg-white/90 dark:bg-gray-800/90 backdrop-blur-md shadow-lg transform lg:translate-x-0 transition-transform duration-300 ease-in-out ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        } lg:relative lg:w-64 flex-shrink-0 border-r border-gray-200/70 dark:border-gray-700/70`}
        initial={false}
      >
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center justify-between px-4 py-5 border-b border-gray-200/70 dark:border-gray-700/70">
            <Link href="/" className="flex items-center">
              <div className="relative">
                <div className="absolute inset-0 bg-primary-500/20 rounded-full filter blur-md animate-pulse-slow"></div>
                <ShieldCheckIcon className="w-8 h-8 text-primary-500 relative z-10" />
              </div>
              <span className="text-xl font-bold ml-2">PhishGuard</span>
            </Link>
            <button 
              className="p-1 rounded-md lg:hidden hover:bg-gray-100 dark:hover:bg-gray-700"
              onClick={toggleSidebar}
            >
              <XMarkIcon className="w-6 h-6" />
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6 overflow-y-auto scrollbar-thin">
            <div className="mb-8">
              <h3 className="px-4 mb-2 text-xs font-semibold text-gray-500 uppercase dark:text-gray-400">
                Monitoring
              </h3>
              <NavItem 
                href="/" 
                icon={<HomeIcon />} 
                title="Overview" 
                active={router.pathname === '/'} 
              />
              <NavItem 
                href="/analysis" 
                icon={<ChartBarIcon />} 
                title="Analysis" 
                active={router.pathname.startsWith('/analysis')} 
              />
              <NavItem 
                href="/incidents" 
                icon={<ShieldCheckIcon />} 
                title="Incidents" 
                active={router.pathname.startsWith('/incidents')} 
              />
            </div>

            <div className="mb-8">
              <h3 className="px-4 mb-2 text-xs font-semibold text-gray-500 uppercase dark:text-gray-400">
                Tools
              </h3>
              <NavItem 
                href="/scan" 
                icon={<DocumentTextIcon />} 
                title="Email Scanner" 
                active={router.pathname.startsWith('/scan')} 
              />
              <NavItem 
                href="/url-scan" 
                icon={<LinkIcon />} 
                title="URL Scanner" 
                active={router.pathname.startsWith('/url-scan')} 
              />
              <NavItem 
                href="/reports" 
                icon={<DocumentTextIcon />} 
                title="Reports" 
                active={router.pathname.startsWith('/reports')} 
              />
            </div>

            <div>
              <h3 className="px-4 mb-2 text-xs font-semibold text-gray-500 uppercase dark:text-gray-400">
                Settings
              </h3>
              <NavItem 
                href="/settings" 
                icon={<CogIcon />} 
                title="Settings" 
                active={router.pathname.startsWith('/settings')} 
              />
            </div>
          </nav>

          {/* User profile */}
          <div className="p-4 border-t border-gray-200/70 dark:border-gray-700/70">
            <div className="flex items-center">
              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-primary-400 to-primary-600 flex items-center justify-center text-white font-bold shadow-inner">
                A
              </div>
              <div className="ml-3">
                <p className="font-medium">Admin User</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">admin@example.com</p>
              </div>
            </div>
          </div>
        </div>
      </motion.aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="bg-white/80 dark:bg-gray-800/80 backdrop-blur-md shadow-sm z-10 border-b border-gray-200/70 dark:border-gray-700/70">
          <div className="px-4 py-4 flex items-center justify-between">
            <button 
              className="p-1 rounded-md lg:hidden hover:bg-gray-100 dark:hover:bg-gray-700"
              onClick={toggleSidebar}
            >
              <Bars3Icon className="w-6 h-6" />
            </button>
            
            <div className="flex items-center space-x-4">
              <motion.button 
                className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 relative"
                whileTap={{ scale: 0.95 }}
                onClick={toggleDarkMode}
              >
                {darkMode ? <SunIcon className="w-5 h-5" /> : <MoonIcon className="w-5 h-5" />}
              </motion.button>
              
              <div className="relative">
                <motion.button 
                  className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 relative"
                  whileTap={{ scale: 0.95 }}
                  onClick={() => setShowNotifications(!showNotifications)}
                >
                  <BellIcon className="w-5 h-5" />
                  {notifications.length > 0 && (
                    <span className="absolute top-0 right-0 w-2 h-2 bg-danger-500 rounded-full"></span>
                  )}
                </motion.button>
                
                <AnimatePresence>
                  {showNotifications && (
                    <motion.div 
                      className="absolute right-0 mt-2 w-80 bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700 overflow-hidden z-50"
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      transition={{ duration: 0.2 }}
                    >
                      <div className="p-3 border-b border-gray-200 dark:border-gray-700">
                        <h3 className="font-medium">Notifications</h3>
                      </div>
                      <div className="max-h-80 overflow-y-auto">
                        {notifications.length > 0 ? (
                          notifications.map(notification => (
                            <div key={notification.id} className="p-3 border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700">
                              <p className="text-sm">{notification.text}</p>
                              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{notification.time}</p>
                            </div>
                          ))
                        ) : (
                          <div className="p-3 text-center text-gray-500 dark:text-gray-400">
                            No new notifications
                          </div>
                        )}
                      </div>
                      <div className="p-2 text-center border-t border-gray-200 dark:border-gray-700">
                        <button className="text-sm text-primary-500 hover:text-primary-600 dark:hover:text-primary-400">
                          View all notifications
                        </button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
              
              <motion.button 
                className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
                whileTap={{ scale: 0.95 }}
              >
                <ArrowLeftOnRectangleIcon className="w-5 h-5" />
              </motion.button>
            </div>
          </div>
        </header>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto p-6 bg-gray-50/95 dark:bg-gray-900/95 backdrop-blur">
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout; 