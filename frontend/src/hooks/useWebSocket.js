import { useEffect, useRef, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { addAgent, updateAgentStatus } from '../store/agentSlice';
import { addTask, updateTask } from '../store/taskSlice';
import { enqueueSnackbar } from 'notistack';

const useWebSocket = () => {
  const dispatch = useDispatch();
  const { token } = useSelector((state) => state.auth);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  const connect = useCallback(() => {
    if (!token) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws?token=${token}`;
    
    wsRef.current = new WebSocket(wsUrl);

    wsRef.current.onopen = () => {
      console.log('WebSocket connected');
      enqueueSnackbar('Connected to real-time updates', { variant: 'success' });
    };

    wsRef.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    };

    wsRef.current.onclose = (event) => {
      console.log('WebSocket disconnected:', event.code, event.reason);
      
      if (event.code !== 1000) {
        // Abnormal closure, attempt reconnect
        reconnectTimeoutRef.current = setTimeout(() => {
          console.log('Attempting to reconnect WebSocket...');
          connect();
        }, 5000);
      }
    };

    wsRef.current.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }, [token]);

  const handleWebSocketMessage = (data) => {
    switch (data.type) {
      case 'agent_connected':
        dispatch(addAgent(data.payload));
        enqueueSnackbar(`Agent connected: ${data.payload.hostname}`, {
          variant: 'success',
          autoHideDuration: 3000,
        });
        break;

      case 'agent_disconnected':
        dispatch(updateAgentStatus({
          uuid: data.payload.uuid,
          status: 'offline',
        }));
        enqueueSnackbar(`Agent disconnected: ${data.payload.hostname}`, {
          variant: 'warning',
        });
        break;

      case 'task_created':
        dispatch(addTask(data.payload));
        enqueueSnackbar(`Task created for agent`, {
          variant: 'info',
        });
        break;

      case 'task_completed':
        dispatch(updateTask(data.payload));
        enqueueSnackbar(`Task completed: ${data.payload.command}`, {
          variant: data.payload.status === 'success' ? 'success' : 'error',
        });
        break;

      case 'file_uploaded':
        enqueueSnackbar(`File uploaded: ${data.payload.filename}`, {
          variant: 'info',
        });
        break;

      case 'system_alert':
        enqueueSnackbar(data.payload.message, {
          variant: data.payload.level === 'error' ? 'error' : 'warning',
          persist: data.payload.level === 'error',
        });
        break;

      case 'ping':
        // Send pong response
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({ type: 'pong' }));
        }
        break;

      default:
        console.log('Unhandled WebSocket message:', data);
    }
  };

  const sendMessage = useCallback((message) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket not connected');
    }
  }, []);

  useEffect(() => {
    if (token) {
      connect();
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close(1000, 'Component unmounted');
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [token, connect]);

  return { sendMessage };
};

export default useWebSocket;
