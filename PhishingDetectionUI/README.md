# PhishGuard UI

A modern, responsive user interface for the PhishGuard phishing detection system. This UI provides a real-time dashboard for monitoring and analyzing potential phishing threats with a sleek, professional design.

## Features

- **Real-time Analytics Dashboard**: Live monitoring of phishing detection metrics with animated visualizations
- **Advanced Email Scanner**: Analyze emails for phishing attempts with detailed results and risk assessment
- **Incident Management**: Track and manage detected phishing incidents with filtering and search
- **Threat Intelligence Integration**: Display real-time threat intelligence data with contextual information
- **Responsive Design**: Works flawlessly on desktop, tablet, and mobile devices
- **Dark Mode Support**: Auto-detects system preferences with smooth transitions between themes
- **Modern UI Elements**: Glass morphism, subtle animations, and microinteractions enhance the user experience

## Tech Stack

- **Next.js**: React framework for server-rendered applications
- **TypeScript**: Type-safe JavaScript for robust code
- **Tailwind CSS**: Utility-first CSS framework with custom cybersecurity theme
- **Framer Motion**: Powerful animation library for React components
- **Heroicons**: Beautiful hand-crafted SVG icons
- **Recharts**: Composable charting library for data visualization

## Getting Started

### Prerequisites

- Node.js 14.x or later
- npm or yarn

### Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/phishguard-ui.git
cd phishguard-ui
```

2. Install dependencies
```bash
npm install
# or
yarn install
```

3. Create a `.env.local` file with the following variables:
```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

4. Start the development server
```bash
npm run dev
# or
yarn dev
```

5. Open [http://localhost:3000](http://localhost:3000) in your browser

## Integration with Backend

The UI connects to the PhishGuard backend system for real-time data processing and analysis. By default, it will connect to `http://localhost:8000` with the following API endpoints:

- `/analyze/email` - POST endpoint for email analysis
- `/analysis/{incident_id}` - GET endpoint for retrieving analysis results
- `/analyze/url` - POST endpoint for URL analysis

The backend handles the complex threat detection logic while the UI presents the results in a user-friendly format.

## Building for Production

```bash
npm run build
# or
yarn build
```

## Deployment

The UI can be deployed to any platform that supports Next.js applications, such as Vercel, Netlify, or a custom server.

### Deploying to Vercel

1. Push your code to a Git repository (GitHub, GitLab, or Bitbucket)
2. Import the project into Vercel
3. Set the environment variables
4. Deploy!

## UI Highlights

- **Glass Morphism Effects**: Modern translucent card components with backdrop blur
- **Microinteractions**: Subtle animations provide feedback on user actions
- **Real-time Updates**: Data refreshes automatically to show the latest information
- **Accessibility**: Designed with accessibility in mind, including keyboard navigation
- **Performance Optimized**: Fast loading times and smooth animations

## License

This project is licensed under the MIT License - see the LICENSE file for details. 