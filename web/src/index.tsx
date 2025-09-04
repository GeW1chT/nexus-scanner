import { createRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import App from './App';
import reportWebVitals from './reportWebVitals';

// Global styles
import './index.css';

// Performance monitoring
import { getCLS, getFID, getFCP, getLCP, getTTFB } from 'web-vitals';

// Error reporting (development only)
if (process.env['NODE_ENV'] === 'development') {
  // Enable React DevTools
  if (typeof window !== 'undefined') {
    (window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__ = {
      ...((window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__ || {}),
      supportsFiber: true,
    };
  }
}

// Get root element
const container = document.getElementById('root');
if (!container) {
  throw new Error('Root element not found');
}

// Create React root
const root = createRoot(container);

// Render app
root.render(
  <StrictMode>
    <App />
  </StrictMode>
);

// Performance monitoring
const sendToAnalytics = (metric: any) => {
  // In production, send to your analytics service
  if (process.env['NODE_ENV'] === 'production') {
    // Example: gtag('event', metric.name, metric);
    console.log('Performance metric:', metric);
  } else {
    console.log('Performance metric:', metric);
  }
};

// Measure Core Web Vitals
getCLS(sendToAnalytics);
getFID(sendToAnalytics);
getFCP(sendToAnalytics);
getLCP(sendToAnalytics);
getTTFB(sendToAnalytics);

// Report web vitals
reportWebVitals(sendToAnalytics);

// Service Worker registration
if ('serviceWorker' in navigator && process.env['NODE_ENV'] === 'production') {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/sw.js')
      .then((registration) => {
        console.log('SW registered: ', registration);
        
        // Check for updates
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          if (newWorker) {
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // New content is available, notify user
                if (window.confirm('Yeni sürüm mevcut. Sayfayı yenilemek ister misiniz?')) {
                  window.location.reload();
                }
              }
            });
          }
        });
      })
      .catch((registrationError) => {
        console.log('SW registration failed: ', registrationError);
      });
  });
}

// Global error handling
window.addEventListener('error', (event) => {
  console.error('Global error:', event.error);
  // In production, send to error reporting service
  if (process.env['NODE_ENV'] === 'production') {
    // Example: Sentry.captureException(event.error);
  }
});

window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
  // In production, send to error reporting service
  if (process.env['NODE_ENV'] === 'production') {
    // Example: Sentry.captureException(event.reason);
  }
});

// Development helpers
if (process.env['NODE_ENV'] === 'development') {
  // Add development utilities to window object
  (window as any).nexusDebug = {
    clearCache: () => {
      localStorage.clear();
      sessionStorage.clear();
      console.log('Cache cleared');
    },
    getPerformance: () => {
      if (window.performance && window.performance.timing) {
        const timing = window.performance.timing;
        return {
          loadTime: timing.loadEventEnd - timing.navigationStart,
          domReady: timing.domContentLoadedEventEnd - timing.navigationStart,
          firstPaint: timing.responseEnd - timing.navigationStart,
        };
      }
      return null;
    },
    version: process.env['REACT_APP_VERSION'] || '1.0.0',
  };
  
  console.log('🚀 Nexus-Scanner Frontend başlatıldı');
  console.log('🔧 Geliştirme modu aktif');
  console.log('📊 Performance monitoring etkin');
  console.log('🛠️ Debug utilities: window.nexusDebug');
}