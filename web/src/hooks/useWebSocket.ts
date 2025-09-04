import { useEffect, useRef, useCallback, useState } from 'react';
import { websocketService, WebSocketState, WebSocketEventType } from '../services/websocketService';
import { WebSocketMessage, WebSocketMessageType } from '../types/api';

// WebSocket connection hook
export const useWebSocketConnection = () => {
  const [state, setState] = useState<WebSocketState>(websocketService.getState());
  const [connectionInfo, setConnectionInfo] = useState(websocketService.getConnectionInfo());
  const [isConnecting, setIsConnecting] = useState(false);

  useEffect(() => {
    // Listen for state changes
    const handleStateChange = (data: { oldState: WebSocketState; newState: WebSocketState }) => {
      setState(data.newState);
      setConnectionInfo(websocketService.getConnectionInfo());
      
      if (data.newState === WebSocketState.CONNECTING) {
        setIsConnecting(true);
      } else {
        setIsConnecting(false);
      }
    };

    const listenerId = websocketService.addEventListener(WebSocketEventType.STATE_CHANGE, handleStateChange);

    // Initial state
    setState(websocketService.getState());
    setConnectionInfo(websocketService.getConnectionInfo());

    return () => {
      websocketService.removeEventListener(listenerId);
    };
  }, []);

  const connect = useCallback(async () => {
    if (state === WebSocketState.CONNECTED || isConnecting) {
      return;
    }
    
    setIsConnecting(true);
    try {
      await websocketService.connect();
    } catch (error) {
      console.error('WebSocket connection failed:', error);
    } finally {
      setIsConnecting(false);
    }
  }, [state, isConnecting]);

  const disconnect = useCallback(() => {
    websocketService.disconnect();
  }, []);

  const sendMessage = useCallback((message: WebSocketMessage) => {
    return websocketService.send(message);
  }, []);

  return {
    state,
    connectionInfo,
    isConnecting,
    isConnected: state === WebSocketState.CONNECTED,
    connect,
    disconnect,
    sendMessage,
  };
};

// WebSocket message listener hook
export const useWebSocketMessage = <T = any>(
  messageType: WebSocketMessageType | string,
  callback: (data: T) => void,
  deps: React.DependencyList = []
) => {
  const callbackRef = useRef(callback);
  const listenerIdRef = useRef<string | null>(null);

  // Update callback ref when callback changes
  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);

  useEffect(() => {
    // Remove previous listener
    if (listenerIdRef.current) {
      websocketService.removeEventListener(listenerIdRef.current);
    }

    // Add new listener
    listenerIdRef.current = websocketService.addEventListener(
      messageType,
      (data: T) => callbackRef.current(data)
    );

    return () => {
      if (listenerIdRef.current) {
        websocketService.removeEventListener(listenerIdRef.current);
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messageType, ...deps]);
};

// Scan updates hook
export const useScanUpdates = (
  scanId: number | null,
  onUpdate?: (scanData: any) => void
) => {
  const [scanData, setScanData] = useState<any>(null);
  const [isSubscribed, setIsSubscribed] = useState(false);
  const scanIdRef = useRef(scanId);

  // Update scan ID ref
  useEffect(() => {
    scanIdRef.current = scanId;
  }, [scanId]);

  // Subscribe to scan updates
  useEffect(() => {
    if (!scanId) {
      setIsSubscribed(false);
      return;
    }

    const subscribe = () => {
      if (websocketService.isConnected()) {
        websocketService.subscribeScanUpdates(scanId);
        setIsSubscribed(true);
      }
    };

    const unsubscribe = () => {
      if (scanIdRef.current) {
        websocketService.unsubscribeScanUpdates(scanIdRef.current);
      }
      setIsSubscribed(false);
    };

    // Subscribe when connected
    if (websocketService.isConnected()) {
      subscribe();
    }

    // Listen for connection state changes
    const handleStateChange = (data: { newState: WebSocketState }) => {
      if (data.newState === WebSocketState.CONNECTED && scanIdRef.current) {
        subscribe();
      } else if (data.newState === WebSocketState.DISCONNECTED) {
        setIsSubscribed(false);
      }
    };

    const stateListenerId = websocketService.addEventListener(
      WebSocketEventType.STATE_CHANGE,
      handleStateChange
    );

    return () => {
      unsubscribe();
      websocketService.removeEventListener(stateListenerId);
    };
  }, [scanId]);

  // Listen for scan update messages
  useWebSocketMessage(
    WebSocketMessageType.SCAN_UPDATE,
    useCallback((data: any) => {
      if (data.scanId === scanId) {
        setScanData(data);
        onUpdate?.(data);
      }
    }, [scanId, onUpdate])
  );

  return {
    scanData,
    isSubscribed,
  };
};

// Notifications hook
export const useNotifications = (
  onNotification?: (notification: any) => void
) => {
  const [notifications, setNotifications] = useState<any[]>([]);
  const [isSubscribed, setIsSubscribed] = useState(false);

  // Subscribe to notifications
  useEffect(() => {
    const subscribe = () => {
      if (websocketService.isConnected()) {
        websocketService.subscribeNotifications();
        setIsSubscribed(true);
      }
    };

    // Subscribe when connected
    if (websocketService.isConnected()) {
      subscribe();
    }

    // Listen for connection state changes
    const handleStateChange = (data: { newState: WebSocketState }) => {
      if (data.newState === WebSocketState.CONNECTED) {
        subscribe();
      } else if (data.newState === WebSocketState.DISCONNECTED) {
        setIsSubscribed(false);
      }
    };

    const stateListenerId = websocketService.addEventListener(
      WebSocketEventType.STATE_CHANGE,
      handleStateChange
    );

    return () => {
      websocketService.removeEventListener(stateListenerId);
    };
  }, []);

  // Listen for notification messages
  useWebSocketMessage(
    WebSocketMessageType.NOTIFICATION,
    useCallback((notification: any) => {
      setNotifications(prev => [notification, ...prev.slice(0, 49)]); // Keep last 50
      onNotification?.(notification);
    }, [onNotification])
  );

  const clearNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

  const removeNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  return {
    notifications,
    isSubscribed,
    clearNotifications,
    removeNotification,
  };
};

// System status hook
export const useSystemStatus = (
  onStatusChange?: (status: any) => void
) => {
  const [systemStatus, setSystemStatus] = useState<any>(null);

  // Listen for system status messages
  useWebSocketMessage(
    WebSocketMessageType.SYSTEM_STATUS,
    useCallback((status: any) => {
      setSystemStatus(status);
      onStatusChange?.(status);
    }, [onStatusChange])
  );

  return {
    systemStatus,
  };
};

// WebSocket heartbeat hook
export const useWebSocketHeartbeat = () => {
  const [lastHeartbeat, setLastHeartbeat] = useState<number>(0);
  const [isHealthy, setIsHealthy] = useState(true);

  // Listen for heartbeat messages
  useWebSocketMessage(
    WebSocketMessageType.HEARTBEAT,
    useCallback((data: any) => {
      const timestamp = data.timestamp || Date.now();
      setLastHeartbeat(timestamp);
      setIsHealthy(true);
    }, [])
  );

  // Check heartbeat health
  useEffect(() => {
    const checkHealth = () => {
      if (lastHeartbeat > 0) {
        const timeSinceLastHeartbeat = Date.now() - lastHeartbeat;
        const isCurrentlyHealthy = timeSinceLastHeartbeat < 60000; // 1 minute threshold
        setIsHealthy(isCurrentlyHealthy);
      }
    };

    const interval = setInterval(checkHealth, 10000); // Check every 10 seconds
    return () => clearInterval(interval);
  }, [lastHeartbeat]);

  return {
    lastHeartbeat,
    isHealthy,
  };
};

// Auto-reconnect hook
export const useWebSocketAutoReconnect = (
  enabled: boolean = true,
  maxAttempts: number = 10
) => {
  const [reconnectAttempts, setReconnectAttempts] = useState(0);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const enabledRef = useRef(enabled);
  const maxAttemptsRef = useRef(maxAttempts);

  // Update refs
  useEffect(() => {
    enabledRef.current = enabled;
    maxAttemptsRef.current = maxAttempts;
  }, [enabled, maxAttempts]);

  useEffect(() => {
    const handleStateChange = async (data: { oldState: WebSocketState; newState: WebSocketState }) => {
      if (!enabledRef.current) return;

      if (data.newState === WebSocketState.DISCONNECTED && 
          data.oldState === WebSocketState.CONNECTED) {
        // Connection lost, attempt to reconnect
        if (reconnectAttempts < maxAttemptsRef.current) {
          setIsReconnecting(true);
          setReconnectAttempts(prev => prev + 1);
          
          try {
            await websocketService.connect();
            setReconnectAttempts(0); // Reset on successful reconnection
          } catch (error) {
            console.error('Auto-reconnect failed:', error);
          } finally {
            setIsReconnecting(false);
          }
        }
      } else if (data.newState === WebSocketState.CONNECTED) {
        // Successfully connected, reset attempts
        setReconnectAttempts(0);
        setIsReconnecting(false);
      }
    };

    const listenerId = websocketService.addEventListener(
      WebSocketEventType.STATE_CHANGE,
      handleStateChange
    );

    return () => {
      websocketService.removeEventListener(listenerId);
    };
  }, [reconnectAttempts]);

  const resetReconnectAttempts = useCallback(() => {
    setReconnectAttempts(0);
  }, []);

  return {
    reconnectAttempts,
    isReconnecting,
    resetReconnectAttempts,
  };
};

// WebSocket error handling hook
export const useWebSocketError = (
  onError?: (error: Event) => void
) => {
  const [lastError, setLastError] = useState<Event | null>(null);
  const [errorCount, setErrorCount] = useState(0);

  // Listen for error events
  useEffect(() => {
    const handleError = (error: Event) => {
      setLastError(error);
      setErrorCount(prev => prev + 1);
      onError?.(error);
    };

    const listenerId = websocketService.addEventListener(
      WebSocketEventType.ERROR,
      handleError
    );

    return () => {
      websocketService.removeEventListener(listenerId);
    };
  }, [onError]);

  const clearError = useCallback(() => {
    setLastError(null);
  }, []);

  const resetErrorCount = useCallback(() => {
    setErrorCount(0);
  }, []);

  return {
    lastError,
    errorCount,
    clearError,
    resetErrorCount,
  };
};

// Custom WebSocket hook with full functionality
export const useWebSocket = (options: {
  autoConnect?: boolean;
  autoReconnect?: boolean;
  maxReconnectAttempts?: number;
  onMessage?: (message: WebSocketMessage) => void;
  onError?: (error: Event) => void;
  onStateChange?: (oldState: WebSocketState, newState: WebSocketState) => void;
} = {}) => {
  const {
    autoConnect = true,
    autoReconnect = true,
    maxReconnectAttempts = 10,
    onMessage,
    onError,
    onStateChange,
  } = options;

  // Use individual hooks
  const connection = useWebSocketConnection();
  const heartbeat = useWebSocketHeartbeat();
  const autoReconnectHook = useWebSocketAutoReconnect(autoReconnect, maxReconnectAttempts);
  const errorHook = useWebSocketError(onError);

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect && connection.state === WebSocketState.DISCONNECTED) {
      connection.connect();
    }
  }, [autoConnect, connection]);

  // Listen for all messages
  useWebSocketMessage(
    WebSocketEventType.MESSAGE,
    useCallback((message: WebSocketMessage) => {
      onMessage?.(message);
    }, [onMessage])
  );

  // Listen for state changes
  useEffect(() => {
    const handleStateChange = (data: { oldState: WebSocketState; newState: WebSocketState }) => {
      onStateChange?.(data.oldState, data.newState);
    };

    const listenerId = websocketService.addEventListener(
      WebSocketEventType.STATE_CHANGE,
      handleStateChange
    );

    return () => {
      websocketService.removeEventListener(listenerId);
    };
  }, [onStateChange]);

  return {
    // Connection
    ...connection,
    
    // Heartbeat
    lastHeartbeat: heartbeat.lastHeartbeat,
    isHealthy: heartbeat.isHealthy,
    
    // Auto-reconnect
    reconnectAttempts: autoReconnectHook.reconnectAttempts,
    isReconnecting: autoReconnectHook.isReconnecting,
    resetReconnectAttempts: autoReconnectHook.resetReconnectAttempts,
    
    // Error handling
    lastError: errorHook.lastError,
    errorCount: errorHook.errorCount,
    clearError: errorHook.clearError,
    resetErrorCount: errorHook.resetErrorCount,
  };
};

// Export default
export default useWebSocket;