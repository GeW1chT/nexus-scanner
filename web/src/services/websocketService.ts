import { WebSocketMessage, WebSocketMessageType } from '../types/api';

// WebSocket connection states
export enum WebSocketState {
  CONNECTING = 'connecting',
  CONNECTED = 'connected',
  DISCONNECTED = 'disconnected',
  ERROR = 'error',
  RECONNECTING = 'reconnecting'
}

// WebSocket event types
export enum WebSocketEventType {
  OPEN = 'open',
  CLOSE = 'close',
  ERROR = 'error',
  MESSAGE = 'message',
  STATE_CHANGE = 'stateChange'
}

// WebSocket configuration
interface WebSocketConfig {
  url: string;
  protocols?: string[];
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
  heartbeatInterval?: number;
  timeout?: number;
  debug?: boolean;
}

// Event listener interface
interface EventListener {
  id: string;
  type: string;
  callback: (data: any) => void;
}

// WebSocket Service Class
export class WebSocketService {
  private ws: WebSocket | null = null;
  private config: WebSocketConfig;
  private state: WebSocketState = WebSocketState.DISCONNECTED;
  private reconnectAttempts = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private listeners: EventListener[] = [];
  private messageQueue: WebSocketMessage[] = [];
  private lastHeartbeat: number = 0;
  private connectionId: string | null = null;

  constructor(config: WebSocketConfig) {
    this.config = {
      reconnectInterval: 5000,
      maxReconnectAttempts: 10,
      heartbeatInterval: 30000,
      timeout: 10000,
      debug: process.env['NODE_ENV'] === 'development',
      ...config
    };

    // Bind methods
    this.connect = this.connect.bind(this);
    this.disconnect = this.disconnect.bind(this);
    this.send = this.send.bind(this);
    this.onOpen = this.onOpen.bind(this);
    this.onClose = this.onClose.bind(this);
    this.onError = this.onError.bind(this);
    this.onMessage = this.onMessage.bind(this);
  }

  // Connect to WebSocket server
  public connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }

      this.setState(WebSocketState.CONNECTING);
      this.log('Connecting to WebSocket server...');

      try {
        // Add auth token to URL if available
        const token = localStorage.getItem('nexus_token');
        const url = token ? `${this.config.url}?token=${token}` : this.config.url;
        
        this.ws = new WebSocket(url, this.config.protocols);
        
        // Set up event listeners
        this.ws.onopen = (event) => {
          this.onOpen(event);
          resolve();
        };
        
        this.ws.onclose = this.onClose;
        this.ws.onerror = (event) => {
          this.onError(event);
          reject(new Error('WebSocket connection failed'));
        };
        
        this.ws.onmessage = this.onMessage;

        // Set connection timeout
        setTimeout(() => {
          if (this.ws && this.ws.readyState === WebSocket.CONNECTING) {
            this.ws.close();
            reject(new Error('WebSocket connection timeout'));
          }
        }, this.config.timeout);

      } catch (error) {
        this.setState(WebSocketState.ERROR);
        reject(error);
      }
    });
  }

  // Disconnect from WebSocket server
  public disconnect(): void {
    this.log('Disconnecting from WebSocket server...');
    
    // Clear timers
    this.clearReconnectTimer();
    this.clearHeartbeatTimer();
    
    // Close connection
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onclose = null;
      this.ws.onerror = null;
      this.ws.onmessage = null;
      
      if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.close(1000, 'Client disconnect');
      }
      
      this.ws = null;
    }
    
    this.setState(WebSocketState.DISCONNECTED);
    this.connectionId = null;
  }

  // Send message to server
  public send(message: WebSocketMessage): boolean {
    if (!this.isConnected()) {
      this.log('WebSocket not connected, queuing message');
      this.messageQueue.push(message);
      return false;
    }

    try {
      const messageWithId = {
        ...message,
        id: message.id || this.generateMessageId(),
        timestamp: new Date().toISOString()
      };
      
      this.ws!.send(JSON.stringify(messageWithId));
      this.log('Message sent:', messageWithId);
      return true;
    } catch (error) {
      this.log('Error sending message:', error);
      return false;
    }
  }

  // Send heartbeat/ping
  public sendHeartbeat(): void {
    this.send({
      type: WebSocketMessageType.HEARTBEAT,
      data: { timestamp: Date.now() },
      timestamp: new Date().toISOString()
    });
  }

  // Subscribe to scan updates
  public subscribeScanUpdates(scanId: number): void {
    this.send({
      type: WebSocketMessageType.SUBSCRIBE,
      data: {
        channel: 'scan_updates',
        scanId
      },
      timestamp: new Date().toISOString()
    });
  }

  // Unsubscribe from scan updates
  public unsubscribeScanUpdates(scanId: number): void {
    this.send({
      type: WebSocketMessageType.UNSUBSCRIBE,
      data: {
        channel: 'scan_updates',
        scanId
      },
      timestamp: new Date().toISOString()
    });
  }

  // Subscribe to system notifications
  public subscribeNotifications(): void {
    this.send({
      type: WebSocketMessageType.SUBSCRIBE,
      data: {
        channel: 'notifications'
      },
      timestamp: new Date().toISOString()
    });
  }

  // Add event listener
  public addEventListener(type: string, callback: (data: any) => void): string {
    const id = this.generateListenerId();
    this.listeners.push({ id, type, callback });
    return id;
  }

  // Remove event listener
  public removeEventListener(id: string): void {
    this.listeners = this.listeners.filter(listener => listener.id !== id);
  }

  // Remove all event listeners of a type
  public removeAllEventListeners(type?: string): void {
    if (type) {
      this.listeners = this.listeners.filter(listener => listener.type !== type);
    } else {
      this.listeners = [];
    }
  }

  // Get connection state
  public getState(): WebSocketState {
    return this.state;
  }

  // Check if connected
  public isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  // Get connection info
  public getConnectionInfo(): {
    state: WebSocketState;
    url: string;
    connectionId: string | null;
    reconnectAttempts: number;
    lastHeartbeat: number;
    queuedMessages: number;
  } {
    return {
      state: this.state,
      url: this.config.url,
      connectionId: this.connectionId,
      reconnectAttempts: this.reconnectAttempts,
      lastHeartbeat: this.lastHeartbeat,
      queuedMessages: this.messageQueue.length
    };
  }

  // Private Methods

  private onOpen(event: Event): void {
    this.log('WebSocket connected');
    this.setState(WebSocketState.CONNECTED);
    this.reconnectAttempts = 0;
    
    // Start heartbeat
    this.startHeartbeat();
    
    // Send queued messages
    this.sendQueuedMessages();
    
    // Emit open event
    this.emit(WebSocketEventType.OPEN, event);
  }

  private onClose(event: CloseEvent): void {
    this.log('WebSocket disconnected:', event.code, event.reason);
    
    // Clear timers
    this.clearHeartbeatTimer();
    
    // Set state
    this.setState(WebSocketState.DISCONNECTED);
    this.connectionId = null;
    
    // Emit close event
    this.emit(WebSocketEventType.CLOSE, event);
    
    // Auto-reconnect if not intentional disconnect
    if (event.code !== 1000 && this.reconnectAttempts < this.config.maxReconnectAttempts!) {
      this.scheduleReconnect();
    }
  }

  private onError(event: Event): void {
    this.log('WebSocket error:', event);
    this.setState(WebSocketState.ERROR);
    this.emit(WebSocketEventType.ERROR, event);
  }

  private onMessage(event: MessageEvent): void {
    try {
      const message: WebSocketMessage = JSON.parse(event.data);
      this.log('Message received:', message);
      
      // Handle system messages
      this.handleSystemMessage(message);
      
      // Emit message event
      this.emit(WebSocketEventType.MESSAGE, message);
      
      // Emit specific message type events
      this.emit(message.type, message.data);
      
    } catch (error) {
      this.log('Error parsing message:', error);
    }
  }

  private handleSystemMessage(message: WebSocketMessage): void {
    switch (message.type) {
      case WebSocketMessageType.HEARTBEAT:
        this.lastHeartbeat = Date.now();
        break;
        
      case WebSocketMessageType.CONNECTION_ACK:
        this.connectionId = message.data?.connectionId;
        break;
        
      case WebSocketMessageType.ERROR:
        console.error('WebSocket server error:', message.data);
        break;
        
      case WebSocketMessageType.SCAN_UPDATE:
        // Handle scan updates
        this.emit('scanUpdate', message.data);
        break;
        
      case WebSocketMessageType.NOTIFICATION:
        // Handle notifications
        this.emit('notification', message.data);
        break;
        
      case WebSocketMessageType.SYSTEM_STATUS:
        // Handle system status updates
        this.emit('systemStatus', message.data);
        break;
    }
  }

  private setState(newState: WebSocketState): void {
    if (this.state !== newState) {
      const oldState = this.state;
      this.state = newState;
      this.log(`State changed: ${oldState} -> ${newState}`);
      this.emit(WebSocketEventType.STATE_CHANGE, { oldState, newState });
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      return;
    }
    
    this.setState(WebSocketState.RECONNECTING);
    this.reconnectAttempts++;
    
    const delay = Math.min(
      this.config.reconnectInterval! * Math.pow(2, this.reconnectAttempts - 1),
      30000 // Max 30 seconds
    );
    
    this.log(`Scheduling reconnect attempt ${this.reconnectAttempts} in ${delay}ms`);
    
    this.reconnectTimer = setTimeout(() => {
      this.clearReconnectTimer();
      this.connect().catch(error => {
        this.log('Reconnect failed:', error);
      });
    }, delay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private startHeartbeat(): void {
    this.clearHeartbeatTimer();
    
    this.heartbeatTimer = setInterval(() => {
      if (this.isConnected()) {
        this.sendHeartbeat();
      }
    }, this.config.heartbeatInterval!);
  }

  private clearHeartbeatTimer(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private sendQueuedMessages(): void {
    while (this.messageQueue.length > 0 && this.isConnected()) {
      const message = this.messageQueue.shift()!;
      this.send(message);
    }
  }

  private emit(type: string, data: any): void {
    this.listeners
      .filter(listener => listener.type === type)
      .forEach(listener => {
        try {
          listener.callback(data);
        } catch (error) {
          this.log('Error in event listener:', error);
        }
      });
  }

  private generateMessageId(): string {
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateListenerId(): string {
    return `listener_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private log(...args: any[]): void {
    if (this.config.debug) {
      console.log('[WebSocket]', ...args);
    }
  }
}

// WebSocket Service Factory
export class WebSocketServiceFactory {
  private static instances: Map<string, WebSocketService> = new Map();

  public static create(name: string, config: WebSocketConfig): WebSocketService {
    if (this.instances.has(name)) {
      return this.instances.get(name)!;
    }

    const service = new WebSocketService(config);
    this.instances.set(name, service);
    return service;
  }

  public static get(name: string): WebSocketService | undefined {
    return this.instances.get(name);
  }

  public static remove(name: string): void {
    const service = this.instances.get(name);
    if (service) {
      service.disconnect();
      this.instances.delete(name);
    }
  }

  public static removeAll(): void {
    this.instances.forEach(service => service.disconnect());
    this.instances.clear();
  }
}

// Default WebSocket service instance
const WS_URL = process.env['REACT_APP_WS_URL'] || 'ws://localhost:8000/ws';

export const websocketService = WebSocketServiceFactory.create('default', {
  url: WS_URL,
  reconnectInterval: 5000,
  maxReconnectAttempts: 10,
  heartbeatInterval: 30000,
  timeout: 10000,
  debug: process.env['NODE_ENV'] === 'development'
});

// Export default
export default websocketService;

// Utility hooks for React components
export const useWebSocket = () => {
  return websocketService;
};

export const useWebSocketState = () => {
  return websocketService.getState();
};

export const useWebSocketConnection = () => {
  return websocketService.getConnectionInfo();
};