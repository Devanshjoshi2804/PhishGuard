from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
from datetime import datetime, timedelta
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from io import BytesIO
import asyncio
import aiofiles
import os
from jinja2 import Environment, FileSystemLoader

class LoggingAgent(BaseAgent):
    """Agent responsible for logging system activities and generating reports."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("logging", config)
        self.log_directory = config.get('log_directory', 'logs')
        self.report_directory = config.get('report_directory', 'reports')
        self.retention_period = timedelta(days=config.get('retention_days', 90))
        self.report_schedule = config.get('report_schedule', {
            'daily': True,
            'weekly': True,
            'monthly': True
        })
        self.template_env = self._setup_template_env()
        self.report_types = {
            'incident_summary': self._generate_incident_summary,
            'threat_analysis': self._generate_threat_analysis,
            'performance_metrics': self._generate_performance_metrics,
            'system_health': self._generate_system_health
        }

    def _setup_template_env(self) -> Environment:
        """Setup Jinja2 template environment."""
        template_dir = os.path.join(os.path.dirname(__file__), '../../templates/reports')
        return Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True
        )

    async def initialize(self) -> None:
        """Initialize the logging agent."""
        self.logger.info("Initializing Logging Agent")
        await self._ensure_directories()
        await self._start_report_scheduler()

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process logging and reporting requests."""
        try:
            incident_id = data.get('incident_id')
            log_type = data.get('log_type', 'general')
            
            # Process the log entry
            log_entry = await self._process_log_entry(data)
            
            # Store log entry
            await self._store_log(log_entry)
            
            # Generate reports if needed
            if data.get('generate_report'):
                report_types = data.get('report_types', ['incident_summary'])
                report_results = await self._generate_reports(report_types, incident_id)
                log_entry['report_results'] = report_results

            return log_entry

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        os.makedirs(self.log_directory, exist_ok=True)
        os.makedirs(self.report_directory, exist_ok=True)
        
        # Create subdirectories for different report types
        for report_type in ['daily', 'weekly', 'monthly', 'incident']:
            os.makedirs(os.path.join(self.report_directory, report_type), exist_ok=True)

    async def _start_report_scheduler(self) -> None:
        """Start scheduled report generation."""
        if self.report_schedule['daily']:
            asyncio.create_task(self._schedule_daily_reports())
        if self.report_schedule['weekly']:
            asyncio.create_task(self._schedule_weekly_reports())
        if self.report_schedule['monthly']:
            asyncio.create_task(self._schedule_monthly_reports())

    async def _process_log_entry(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process and format a log entry."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'incident_id': data.get('incident_id'),
            'log_type': data.get('log_type', 'general'),
            'source_agent': data.get('source_agent', 'unknown'),
            'severity': data.get('severity', 'info'),
            'details': data.get('details', {}),
            'metadata': {
                'system_version': data.get('system_version'),
                'environment': data.get('environment', 'production')
            }
        }

        # Add context-specific information
        if 'error' in data:
            log_entry['error'] = {
                'message': str(data['error']),
                'traceback': data.get('traceback'),
                'context': data.get('error_context', {})
            }

        if 'metrics' in data:
            log_entry['metrics'] = data['metrics']

        if 'tags' in data:
            log_entry['tags'] = data['tags']

        return log_entry

    async def _store_log(self, log_entry: Dict[str, Any]) -> None:
        """Store log entry in database and file system."""
        try:
            # Store in database
            await db.store_log(log_entry)
            
            # Store in file system
            log_file = os.path.join(
                self.log_directory,
                f"{datetime.utcnow().strftime('%Y-%m-%d')}.log"
            )
            
            async with aiofiles.open(log_file, 'a') as f:
                await f.write(json.dumps(log_entry) + '\n')

        except Exception as e:
            self.logger.error(f"Error storing log entry: {str(e)}")
            raise

    async def _generate_reports(self, report_types: List[str], incident_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate specified reports."""
        results = {}
        
        for report_type in report_types:
            if report_type in self.report_types:
                try:
                    report = await self.report_types[report_type](incident_id)
                    results[report_type] = report
                except Exception as e:
                    self.logger.error(f"Error generating {report_type} report: {str(e)}")
                    results[report_type] = {'error': str(e)}

        return results

    async def _generate_incident_summary(self, incident_id: str) -> Dict[str, Any]:
        """Generate incident summary report."""
        try:
            # Gather incident data
            incident_data = await db.get_incident_data(incident_id)
            
            # Process analysis results
            analysis_results = {
                'email_analysis': incident_data.get('email_analysis'),
                'domain_analysis': incident_data.get('domain_analysis'),
                'url_analysis': incident_data.get('url_analysis'),
                'threat_intel': incident_data.get('threat_intelligence_analysis'),
                'anomaly_detection': incident_data.get('anomaly_detection_analysis')
            }
            
            # Generate visualizations
            visualizations = await self._generate_incident_visualizations(analysis_results)
            
            # Create report
            template = self.template_env.get_template('incident_summary.html')
            report_content = template.render(
                incident_id=incident_id,
                timestamp=datetime.utcnow().isoformat(),
                analysis_results=analysis_results,
                visualizations=visualizations
            )
            
            # Save report
            report_file = os.path.join(
                self.report_directory,
                'incident',
                f"incident_{incident_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
            )
            
            async with aiofiles.open(report_file, 'w') as f:
                await f.write(report_content)
            
            return {
                'status': 'success',
                'report_file': report_file,
                'summary': analysis_results
            }

        except Exception as e:
            self.logger.error(f"Error generating incident summary: {str(e)}")
            raise

    async def _generate_threat_analysis(self, incident_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate threat analysis report."""
        try:
            # Get threat data for specified period
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=30)
            
            threat_data = await db.get_threat_data(start_date, end_date)
            
            # Analyze trends
            trends = self._analyze_threat_trends(threat_data)
            
            # Generate visualizations
            visualizations = await self._generate_threat_visualizations(threat_data)
            
            # Create report
            template = self.template_env.get_template('threat_analysis.html')
            report_content = template.render(
                timestamp=datetime.utcnow().isoformat(),
                threat_data=threat_data,
                trends=trends,
                visualizations=visualizations
            )
            
            # Save report
            report_file = os.path.join(
                self.report_directory,
                'monthly',
                f"threat_analysis_{datetime.utcnow().strftime('%Y%m')}.html"
            )
            
            async with aiofiles.open(report_file, 'w') as f:
                await f.write(report_content)
            
            return {
                'status': 'success',
                'report_file': report_file,
                'trends': trends
            }

        except Exception as e:
            self.logger.error(f"Error generating threat analysis: {str(e)}")
            raise

    async def _generate_performance_metrics(self, incident_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate performance metrics report."""
        try:
            # Get performance data
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=7)
            
            metrics = await db.get_performance_metrics(start_date, end_date)
            
            # Calculate statistics
            stats = self._calculate_performance_stats(metrics)
            
            # Generate visualizations
            visualizations = await self._generate_performance_visualizations(metrics)
            
            # Create report
            template = self.template_env.get_template('performance_metrics.html')
            report_content = template.render(
                timestamp=datetime.utcnow().isoformat(),
                metrics=metrics,
                stats=stats,
                visualizations=visualizations
            )
            
            # Save report
            report_file = os.path.join(
                self.report_directory,
                'weekly',
                f"performance_metrics_{datetime.utcnow().strftime('%Y%m%d')}.html"
            )
            
            async with aiofiles.open(report_file, 'w') as f:
                await f.write(report_content)
            
            return {
                'status': 'success',
                'report_file': report_file,
                'stats': stats
            }

        except Exception as e:
            self.logger.error(f"Error generating performance metrics: {str(e)}")
            raise

    async def _generate_system_health(self, incident_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate system health report."""
        try:
            # Get system health data
            health_data = await db.get_system_health()
            
            # Check component status
            status = self._check_component_status(health_data)
            
            # Generate visualizations
            visualizations = await self._generate_health_visualizations(health_data)
            
            # Create report
            template = self.template_env.get_template('system_health.html')
            report_content = template.render(
                timestamp=datetime.utcnow().isoformat(),
                health_data=health_data,
                status=status,
                visualizations=visualizations
            )
            
            # Save report
            report_file = os.path.join(
                self.report_directory,
                'daily',
                f"system_health_{datetime.utcnow().strftime('%Y%m%d')}.html"
            )
            
            async with aiofiles.open(report_file, 'w') as f:
                await f.write(report_content)
            
            return {
                'status': 'success',
                'report_file': report_file,
                'system_status': status
            }

        except Exception as e:
            self.logger.error(f"Error generating system health report: {str(e)}")
            raise

    def _analyze_threat_trends(self, threat_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat trends from collected data."""
        df = pd.DataFrame(threat_data)
        
        trends = {
            'total_incidents': len(df),
            'risk_levels': df['risk_level'].value_counts().to_dict(),
            'top_threat_types': df['threat_type'].value_counts().head(5).to_dict(),
            'detection_sources': df['detection_source'].value_counts().to_dict(),
            'average_confidence': float(df['confidence'].mean()),
            'trend_direction': 'increasing' if len(df) > df['timestamp'].nunique() else 'stable'
        }
        
        return trends

    def _calculate_performance_stats(self, metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate performance statistics."""
        df = pd.DataFrame(metrics)
        
        stats = {
            'average_response_time': float(df['response_time'].mean()),
            'detection_accuracy': float(df['accuracy'].mean()),
            'false_positive_rate': float(df['false_positive_rate'].mean()),
            'processing_efficiency': {
                'avg_cpu_usage': float(df['cpu_usage'].mean()),
                'avg_memory_usage': float(df['memory_usage'].mean()),
                'avg_throughput': float(df['throughput'].mean())
            }
        }
        
        return stats

    def _check_component_status(self, health_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check status of system components."""
        status = {
            'overall_health': 'healthy',
            'components': {},
            'alerts': []
        }
        
        for component, data in health_data.items():
            component_status = 'healthy'
            if data['error_rate'] > 0.1:
                component_status = 'degraded'
            if data['error_rate'] > 0.3:
                component_status = 'critical'
                status['alerts'].append(f"Critical error rate in {component}")
            
            status['components'][component] = {
                'status': component_status,
                'metrics': data
            }
        
        # Update overall health based on component status
        if any(c['status'] == 'critical' for c in status['components'].values()):
            status['overall_health'] = 'critical'
        elif any(c['status'] == 'degraded' for c in status['components'].values()):
            status['overall_health'] = 'degraded'
        
        return status

    async def _schedule_daily_reports(self) -> None:
        """Schedule daily report generation."""
        while True:
            try:
                # Generate daily reports
                await self._generate_reports(['system_health'])
                
                # Wait until next day
                now = datetime.utcnow()
                next_run = now.replace(hour=0, minute=0, second=0) + timedelta(days=1)
                await asyncio.sleep((next_run - now).total_seconds())
                
            except Exception as e:
                self.logger.error(f"Error in daily report scheduler: {str(e)}")
                await asyncio.sleep(3600)  # Retry in an hour

    async def _schedule_weekly_reports(self) -> None:
        """Schedule weekly report generation."""
        while True:
            try:
                # Generate weekly reports
                await self._generate_reports(['performance_metrics'])
                
                # Wait until next week
                now = datetime.utcnow()
                next_run = now.replace(hour=0, minute=0, second=0) + timedelta(days=(7 - now.weekday()))
                await asyncio.sleep((next_run - now).total_seconds())
                
            except Exception as e:
                self.logger.error(f"Error in weekly report scheduler: {str(e)}")
                await asyncio.sleep(3600)  # Retry in an hour

    async def _schedule_monthly_reports(self) -> None:
        """Schedule monthly report generation."""
        while True:
            try:
                # Generate monthly reports
                await self._generate_reports(['threat_analysis'])
                
                # Wait until next month
                now = datetime.utcnow()
                next_month = now.replace(day=1) + timedelta(days=32)
                next_run = next_month.replace(day=1, hour=0, minute=0, second=0)
                await asyncio.sleep((next_run - now).total_seconds())
                
            except Exception as e:
                self.logger.error(f"Error in monthly report scheduler: {str(e)}")
                await asyncio.sleep(3600)  # Retry in an hour

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up Logging Agent")
        await self._cleanup_old_logs()
        await self._cleanup_old_reports()

    async def _cleanup_old_logs(self) -> None:
        """Clean up old log files."""
        try:
            cutoff_date = datetime.utcnow() - self.retention_period
            
            # Clean up database logs
            await db.cleanup_logs(cutoff_date)
            
            # Clean up log files
            for filename in os.listdir(self.log_directory):
                try:
                    file_date = datetime.strptime(filename.split('.')[0], '%Y-%m-%d')
                    if file_date < cutoff_date:
                        os.remove(os.path.join(self.log_directory, filename))
                except Exception:
                    continue

        except Exception as e:
            self.logger.error(f"Error cleaning up old logs: {str(e)}")

    async def _cleanup_old_reports(self) -> None:
        """Clean up old report files."""
        try:
            cutoff_date = datetime.utcnow() - self.retention_period
            
            for report_type in ['daily', 'weekly', 'monthly', 'incident']:
                report_dir = os.path.join(self.report_directory, report_type)
                for filename in os.listdir(report_dir):
                    try:
                        file_date = datetime.strptime(
                            filename.split('_')[1].split('.')[0],
                            '%Y%m%d'
                        )
                        if file_date < cutoff_date:
                            os.remove(os.path.join(report_dir, filename))
                    except Exception:
                        continue

        except Exception as e:
            self.logger.error(f"Error cleaning up old reports: {str(e)}") 