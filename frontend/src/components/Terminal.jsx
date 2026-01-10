import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  IconButton,
  Tooltip,
  Typography,
  Chip,
  Button,
  Menu,
  MenuItem,
  TextField,
  InputAdornment,
  LinearProgress,
  Alert,
  Grid,
  Card,
  CardContent,
  Tabs,
  Tab,
} from '@mui/material';
import {
  Clear as ClearIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Settings as SettingsIcon,
  History as HistoryIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Save as SaveIcon,
  Code as CodeIcon,
  Terminal as TerminalIcon,
  Close as CloseIcon,
  ContentCopy as CopyIcon,
} from '@mui/icons-material';
import { Terminal as XTerm } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import 'xterm/css/xterm.css';
import AgentService from '../services/agentService';
import { enqueueSnackbar } from 'notistack';

const Terminal = () => {
  const { agentId } = useParams();
  const navigate = useNavigate();
  const terminalRef = useRef(null);
  const [terminal, setTerminal] = useState(null);
  const [command, setCommand] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [commandHistory, setCommandHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [sessionInfo, setSessionInfo] = useState(null);
  const [settings, setSettings] = useState({
    fontSize: 14,
    theme: 'dark',
    enableBell: false,
    cursorBlink: true,
  });
  const [anchorEl, setAnchorEl] = useState(null);
  const [tabValue, setTabValue] = useState(0);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);

  useEffect(() => {
    if (!agentId) {
      navigate('/agents');
      return;
    }

    initializeTerminal();
    loadSessionInfo();
    loadCommandHistory();

    return () => {
      if (terminal) {
        terminal.dispose();
      }
    };
  }, [agentId]);

  const initializeTerminal = () => {
    const term = new XTerm({
      theme: {
        background: '#1e1e1e',
        foreground: '#d4d4d4',
        cursor: '#ffffff',
        selection: '#264f78',
        black: '#000000',
        red: '#cd3131',
        green: '#0dbc79',
        yellow: '#e5e510',
        blue: '#2472c8',
        magenta: '#bc3fbc',
        cyan: '#11a8cd',
        white: '#e5e5e5',
        brightBlack: '#666666',
        brightRed: '#f14c4c',
        brightGreen: '#23d18b',
        brightYellow: '#f5f543',
        brightBlue: '#3b8eea',
        brightMagenta: '#d670d6',
        brightCyan: '#29b8db',
        brightWhite: '#ffffff',
      },
      fontSize: settings.fontSize,
      fontFamily: 'Consolas, "Courier New", monospace',
      cursorBlink: settings.cursorBlink,
      cursorStyle: 'block',
      scrollback: 10000,
      bellStyle: settings.enableBell ? 'sound' : 'none',
      convertEol: true,
      disableStdin: false,
      allowTransparency: true,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();
    
    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);
    term.open(terminalRef.current);
    fitAddon.fit();

    // Welcome message
    term.writeln('\x1b[1;32m╔══════════════════════════════════════╗\x1b[0m');
    term.writeln('\x1b[1;32m║      ARES Interactive Terminal       ║\x1b[0m');
    term.writeln('\x1b[1;32m╚══════════════════════════════════════╝\x1b[0m');
    term.writeln('');
    term.writeln(`\x1b[1;36mConnected to agent: ${agentId}\x1b[0m`);
    term.writeln('Type commands below. Press Ctrl+C to interrupt.');
    term.writeln('Use ↑/↓ arrow keys to navigate command history.');
    term.writeln('');

    // Handle terminal input
    term.onKey(({ key, domEvent }) => {
      const printable = !domEvent.altKey && !domEvent.ctrlKey && !domEvent.metaKey;

      if (domEvent.ctrlKey && domEvent.key === 'c') {
        // Ctrl+C - interrupt
        term.write('^C');
        sendCommand('\x03');
      } else if (domEvent.ctrlKey && domEvent.key === 'l') {
        // Ctrl+L - clear screen
        term.clear();
      } else if (domEvent.key === 'ArrowUp') {
        // Up arrow - previous command
        if (historyIndex < commandHistory.length - 1) {
          const newIndex = historyIndex + 1;
          setHistoryIndex(newIndex);
          setCommand(commandHistory[commandHistory.length - 1 - newIndex]);
        }
      } else if (domEvent.key === 'ArrowDown') {
        // Down arrow - next command
        if (historyIndex > 0) {
          const newIndex = historyIndex - 1;
          setHistoryIndex(newIndex);
          setCommand(commandHistory[commandHistory.length - 1 - newIndex]);
        } else if (historyIndex === 0) {
          setHistoryIndex(-1);
          setCommand('');
        }
      } else if (domEvent.key === 'Tab') {
        // Tab - autocomplete (basic)
        domEvent.preventDefault();
        // Implement autocomplete logic here
      } else if (printable) {
        term.write(key);
        setCommand(prev => prev + key);
      }
    });

    setTerminal(term);
    connectWebSocket(term);
  };

  const connectWebSocket = (term) => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/terminal/${agentId}`;
    
    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      setIsConnected(true);
      term.writeln('\x1b[1;32m✓ Terminal session established\x1b[0m\n');
      term.writeln('\x1b[1;33m$ \x1b[0m');
      term.focus();
    };
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      switch (data.type) {
        case 'terminal_output':
          term.write(data.output);
          break;
          
        case 'terminal_error':
          term.write(`\x1b[1;31m${data.error}\x1b[0m\n`);
          term.write('\x1b[1;33m$ \x1b[0m');
          break;
          
        case 'terminal_prompt':
          term.write('\x1b[1;33m$ \x1b[0m');
          break;
          
        case 'terminal_complete':
          term.write('\n\x1b[1;32mCommand completed\x1b[0m\n');
          term.write('\x1b[1;33m$ \x1b[0m');
          break;
      }
    };
    
    ws.onclose = () => {
      setIsConnected(false);
      term.writeln('\n\x1b[1;31m✗ Terminal connection closed\x1b[0m');
      enqueueSnackbar('Terminal connection lost', { variant: 'error' });
    };
    
    ws.onerror = (error) => {
      term.writeln(`\x1b[1;31mWebSocket error: ${error.message}\x1b[0m`);
    };
  };

  const loadSessionInfo = async () => {
    try {
      const info = await AgentService.getAgent(agentId);
      setSessionInfo(info);
    } catch (error) {
      console.error('Failed to load session info:', error);
    }
  };

  const loadCommandHistory = () => {
    const saved = localStorage.getItem(`terminal_history_${agentId}`);
    if (saved) {
      setCommandHistory(JSON.parse(saved));
    }
  };

  const saveCommandHistory = (history) => {
    localStorage.setItem(`terminal_history_${agentId}`, JSON.stringify(history));
  };

  const sendCommand = (cmd) => {
    if (!isConnected || !terminal) return;

    // Add to history
    const newHistory = [...commandHistory, cmd].slice(-100); // Keep last 100 commands
    setCommandHistory(newHistory);
    saveCommandHistory(newHistory);
    setHistoryIndex(-1);

    // Send via WebSocket
    const ws = new WebSocket(`wss://${window.location.host}/ws/terminal/${agentId}`);
    ws.onopen = () => {
      ws.send(JSON.stringify({
        type: 'terminal_command',
        command: cmd,
        timestamp: Date.now(),
      }));
      ws.close();
    };

    setCommand('');
  };

  const handleSendCommand = () => {
    if (!command.trim()) return;
    sendCommand(command);
  };

  const handleClearTerminal = () => {
    terminal?.clear();
    terminal?.writeln('\x1b[1;33m$ \x1b[0m');
  };

  const handleDownloadSession = () => {
    const content = terminalRef.current?.innerText || '';
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `terminal-session-${agentId}-${Date.now()}.log`;
    a.click();
    URL.revokeObjectURL(url);
    enqueueSnackbar('Session log downloaded', { variant: 'success' });
  };

  const handleUploadFile = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setIsUploading(true);
    setUploadProgress(0);

    // Simulate upload progress
    const interval = setInterval(() => {
      setUploadProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsUploading(false);
          enqueueSnackbar('File uploaded successfully', { variant: 'success' });
          return 0;
        }
        return prev + 10;
      });
    }, 100);
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendCommand();
    } else if (e.key === 'Escape') {
      setCommand('');
    }
  };

  const SettingsPanel = () => (
    <Card sx={{ mb: 2 }}>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Terminal Settings
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Font Size"
              type="number"
              value={settings.fontSize}
              onChange={(e) => setSettings({ ...settings, fontSize: parseInt(e.target.value) })}
              size="small"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Theme"
              select
              value={settings.theme}
              onChange={(e) => setSettings({ ...settings, theme: e.target.value })}
              size="small"
            >
              <MenuItem value="dark">Dark</MenuItem>
              <MenuItem value="light">Light</MenuItem>
              <MenuItem value="solarized">Solarized</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12}>
            <Button
              fullWidth
              variant="outlined"
              onClick={() => {
                // Apply settings to terminal
                if (terminal) {
                  terminal.setOption('fontSize', settings.fontSize);
                  // Would need to update theme colors here
                }
                enqueueSnackbar('Settings applied', { variant: 'success' });
              }}
            >
              Apply Settings
            </Button>
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );

  const CommandHistoryPanel = () => (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Command History
        </Typography>
        <Box sx={{ maxHeight: 300, overflow: 'auto' }}>
          {commandHistory.length === 0 ? (
            <Typography color="textSecondary">No commands in history</Typography>
          ) : (
            commandHistory.slice().reverse().map((cmd, index) => (
              <Paper
                key={index}
                sx={{
                  p: 1,
                  mb: 1,
                  fontFamily: 'monospace',
                  fontSize: '0.875rem',
                  cursor: 'pointer',
                  '&:hover': { bgcolor: 'action.hover' },
                }}
                onClick={() => {
                  setCommand(cmd);
                  terminal?.focus();
                }}
              >
                {cmd}
              </Paper>
            ))
          )}
        </Box>
        <Button
          fullWidth
          variant="outlined"
          sx={{ mt: 2 }}
          onClick={() => {
            setCommandHistory([]);
            saveCommandHistory([]);
            enqueueSnackbar('History cleared', { variant: 'info' });
          }}
        >
          Clear History
        </Button>
      </CardContent>
    </Card>
  );

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: '#1e1e1e' }}>
      {/* Header */}
      <Box sx={{ p: 2, bgcolor: '#252526', borderBottom: '1px solid #333' }}>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={2}>
            <Typography variant="h6" sx={{ color: 'white' }}>
              <TerminalIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Terminal
            </Typography>
            <Chip
              label={isConnected ? 'Connected' : 'Disconnected'}
              color={isConnected ? 'success' : 'error'}
              size="small"
              sx={{ color: 'white' }}
            />
            {sessionInfo && (
              <Typography variant="body2" sx={{ color: '#888' }}>
                {sessionInfo.hostname} ({sessionInfo.username})
              </Typography>
            )}
          </Box>
          <Box>
            <Tooltip title="Settings">
              <IconButton onClick={(e) => setAnchorEl(e.currentTarget)} size="small" sx={{ color: 'white' }}>
                <SettingsIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Download Session Log">
              <IconButton onClick={handleDownloadSession} size="small" sx={{ color: 'white' }}>
                <DownloadIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Clear Terminal">
              <IconButton onClick={handleClearTerminal} size="small" sx={{ color: 'white' }}>
                <ClearIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Close Terminal">
              <IconButton onClick={() => navigate('/agents')} size="small" sx={{ color: 'white' }}>
                <CloseIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
      </Box>

      {/* Main Content */}
      <Box sx={{ display: 'flex', flexGrow: 1, overflow: 'hidden' }}>
        {/* Terminal */}
        <Box ref={terminalRef} sx={{ flexGrow: 1, p: 1, minWidth: 0 }} />
        
        {/* Side Panel */}
        <Box sx={{ width: 300, p: 2, bgcolor: '#252526', borderLeft: '1px solid #333', overflow: 'auto' }}>
          <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)} sx={{ mb: 2 }}>
            <Tab label="Settings" />
            <Tab label="History" />
            <Tab label="Tools" />
          </Tabs>
          
          {tabValue === 0 && <SettingsPanel />}
          {tabValue === 1 && <CommandHistoryPanel />}
          {tabValue === 2 && (
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Quick Tools
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <Button
                    variant="outlined"
                    startIcon={<PlayIcon />}
                    onClick={() => sendCommand('whoami')}
                  >
                    Whoami
                  </Button>
                  <Button
                    variant="outlined"
                    startIcon={<CodeIcon />}
                    onClick={() => sendCommand('ls -la')}
                  >
                    List Files
                  </Button>
                  <Button
                    variant="outlined"
                    startIcon={<CodeIcon />}
                    onClick={() => sendCommand('pwd')}
                  >
                    Current Directory
                  </Button>
                  <input
                    type="file"
                    id="file-upload"
                    style={{ display: 'none' }}
                    onChange={handleUploadFile}
                  />
                  <Button
                    variant="outlined"
                    startIcon={<UploadIcon />}
                    component="label"
                    htmlFor="file-upload"
                  >
                    Upload File
                  </Button>
                  {isUploading && (
                    <Box sx={{ mt: 1 }}>
                      <LinearProgress variant="determinate" value={uploadProgress} />
                      <Typography variant="caption" color="textSecondary">
                        Uploading... {uploadProgress}%
                      </Typography>
                    </Box>
                  )}
                </Box>
              </CardContent>
            </Card>
          )}
        </Box>
      </Box>

      {/* Command Input */}
      <Box sx={{ p: 2, bgcolor: '#252526', borderTop: '1px solid #333' }}>
        <Box display="flex" alignItems="center" gap={1}>
          <Chip
            label="$"
            size="small"
            sx={{ bgcolor: 'primary.main', color: 'white' }}
          />
          <TextField
            fullWidth
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Type command here..."
            disabled={!isConnected}
            InputProps={{
              sx: {
                color: 'white',
                bgcolor: '#333',
                '& .MuiOutlinedInput-notchedOutline': {
                  borderColor: '#555',
                },
                '&:hover .MuiOutlinedInput-notchedOutline': {
                  borderColor: '#777',
                },
              },
              endAdornment: (
                <InputAdornment position="end">
                  <Tooltip title="Send Command (Enter)">
                    <IconButton
                      onClick={handleSendCommand}
                      disabled={!command.trim() || !isConnected}
                      sx={{ color: 'primary.main' }}
                    >
                      <PlayIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Clear Command (Esc)">
                    <IconButton
                      onClick={() => setCommand('')}
                      sx={{ color: 'text.secondary' }}
                    >
                      <ClearIcon />
                    </IconButton>
                  </Tooltip>
                </InputAdornment>
              ),
            }}
          />
        </Box>
        <Box sx={{ mt: 1, display: 'flex', justifyContent: 'space-between' }}>
          <Typography variant="caption" sx={{ color: '#888' }}>
            {isConnected ? 'Connected' : 'Connecting...'}
          </Typography>
          <Typography variant="caption" sx={{ color: '#888' }}>
            ↑/↓: History • Ctrl+C: Interrupt • Ctrl+L: Clear
          </Typography>
        </Box>
      </Box>

      {/* Settings Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        <MenuItem onClick={() => { setAnchorEl(null); setTabValue(0); }}>
          <SettingsIcon fontSize="small" sx={{ mr: 1 }} /> Settings
        </MenuItem>
        <MenuItem onClick={() => { setAnchorEl(null); setTabValue(1); }}>
          <HistoryIcon fontSize="small" sx={{ mr: 1 }} /> Command History
        </MenuItem>
        <MenuItem onClick={handleDownloadSession}>
          <DownloadIcon fontSize="small" sx={{ mr: 1 }} /> Download Session
        </MenuItem>
        <MenuItem onClick={handleClearTerminal}>
          <ClearIcon fontSize="small" sx={{ mr: 1 }} /> Clear Terminal
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default Terminal;
