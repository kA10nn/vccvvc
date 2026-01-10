import React, { useState, useEffect, useRef } from 'react';
import { Box, Paper, TextField, IconButton, Typography, Chip } from '@mui/material';
import { Send as SendIcon, Clear as ClearIcon, Download as DownloadIcon } from '@mui/icons-material';
import { Terminal as XTerm } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import { useWebSocket } from '../hooks/useWebSocket';

const Terminal = ({ agentId }) => {
  const terminalRef = useRef(null);
  const [terminal, setTerminal] = useState(null);
  const [command, setCommand] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const { sendMessage, messages } = useWebSocket();

  useEffect(() => {
    const term = new XTerm({
      theme: {
        background: '#1e1e1e',
        foreground: '#d4d4d4',
        cursor: '#ffffff',
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
        brightWhite: '#ffffff'
      },
      fontSize: 14,
      fontFamily: 'Consolas, "Courier New", monospace',
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback: 10000
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalRef.current);
    fitAddon.fit();

    term.writeln('\x1b[1;32m⚡ ARES Interactive Terminal\x1b[0m');
    term.writeln(`\x1b[1;36mConnected to agent: ${agentId}\x1b[0m`);
    term.writeln('Type commands below. Press Ctrl+C to interrupt.\n');

    term.onKey(({ key, domEvent }) => {
      if (domEvent.ctrlKey && domEvent.key === 'c') {
        term.write('^C');
        sendMessage({
          type: 'terminal_command',
          agent_id: agentId,
          command: '\x03' // Ctrl+C
        });
      }
    });

    setTerminal(term);

    // Handle window resize
    const handleResize = () => fitAddon.fit();
    window.addEventListener('resize', handleResize);

    // Connect WebSocket for terminal
    connectTerminalWebSocket(agentId, term);

    return () => {
      window.removeEventListener('resize', handleResize);
      term.dispose();
    };
  }, [agentId]);

  const connectTerminalWebSocket = (agentId, term) => {
    const ws = new WebSocket(`wss://${window.location.host}/ws/terminal/${agentId}`);
    
    ws.onopen = () => {
      setIsConnected(true);
      term.writeln('\x1b[1;32m✓ Terminal session established\x1b[0m\n');
    };
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'terminal_output') {
        term.write(data.output);
      }
    };
    
    ws.onclose = () => {
      setIsConnected(false);
      term.writeln('\x1b[1;31m✗ Terminal connection closed\x1b[0m');
    };
    
    ws.onerror = (error) => {
      term.writeln(`\x1b[1;31mTerminal error: ${error.message}\x1b[0m`);
    };
  };

  const handleSendCommand = () => {
    if (!command.trim() || !terminal || !isConnected) return;

    // Display command in terminal
    terminal.write(`\r\n\x1b[1;33m$ ${command}\x1b[0m\r\n`);

    // Send to WebSocket
    sendMessage({
      type: 'terminal_command',
      agent_id: agentId,
      command: command
    });

    setCommand('');
  };

  const handleClearTerminal = () => {
    terminal?.clear();
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendCommand();
    }
  };

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: '#1e1e1e' }}>
      <Box sx={{ p: 2, bgcolor: '#252526', borderBottom: '1px solid #333' }}>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={2}>
            <Typography variant="h6" sx={{ color: 'white' }}>
              Terminal
            </Typography>
            <Chip
              label={isConnected ? 'Connected' : 'Disconnected'}
              color={isConnected ? 'success' : 'error'}
              size="small"
            />
            <Typography variant="body2" sx={{ color: '#888' }}>
              Agent: {agentId?.substring(0, 12)}...
            </Typography>
          </Box>
          <Box>
            <Tooltip title="Clear Terminal">
              <IconButton onClick={handleClearTerminal} size="small" sx={{ color: 'white' }}>
                <ClearIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Download Session Log">
              <IconButton size="small" sx={{ color: 'white' }}>
                <DownloadIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
      </Box>

      <Box ref={terminalRef} sx={{ flexGrow: 1, p: 1 }} />

      <Box sx={{ p: 2, bgcolor: '#252526', borderTop: '1px solid #333' }}>
        <Box display="flex" alignItems="center" gap={1}>
          <TextField
            fullWidth
            variant="outlined"
            placeholder="Type command..."
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            onKeyPress={handleKeyPress}
            InputProps={{
              sx: {
                color: 'white',
                bgcolor: '#333',
                '& .MuiOutlinedInput-notchedOutline': {
                  borderColor: '#555'
                }
              }
            }}
            disabled={!isConnected}
          />
          <IconButton
            onClick={handleSendCommand}
            disabled={!command.trim() || !isConnected}
            sx={{
              bgcolor: 'primary.main',
              color: 'white',
              '&:hover': { bgcolor: 'primary.dark' }
            }}
          >
            <SendIcon />
          </IconButton>
        </Box>
        <Typography variant="caption" sx={{ color: '#888', mt: 1, display: 'block' }}>
          Tip: Use Ctrl+C to interrupt running commands
        </Typography>
      </Box>
    </Box>
  );
};

export default Terminal;
