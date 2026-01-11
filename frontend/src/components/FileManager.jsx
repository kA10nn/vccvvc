import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  Button,
  TextField,
  InputAdornment,
  LinearProgress,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Grid,
  Card,
  CardContent,
  Menu,
  MenuItem,
  FormControl,
  InputLabel,
  Select,
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  GetApp as DownloadIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Upload as UploadIcon,
  Folder as FolderIcon,
  InsertDriveFile as FileIcon,
  MoreVert as MoreVertIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';
import { saveAs } from 'file-saver';
import AgentService from '../services/agentService';
import { enqueueSnackbar } from 'notistack';

const FileManager = () => {
  const [files, setFiles] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);
  const [viewDialogOpen, setViewDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [agents, setAgents] = useState([]);
  const [filterAgent, setFilterAgent] = useState('all');
  const [anchorEl, setAnchorEl] = useState(null);

  useEffect(() => {
    loadFiles();
    loadAgents();
  }, []);

  const loadFiles = async () => {
    setIsLoading(true);
    try {
      // This would normally be a dedicated endpoint for all files
      // For now, we'll simulate by getting files from all agents
      const allAgents = await AgentService.getAgents();
      const filePromises = allAgents.map(agent => 
        AgentService.getFiles(agent.uuid).catch(() => [])
      );
      const results = await Promise.all(filePromises);
      const allFiles = results.flat();
      setFiles(allFiles);
    } catch (error) {
      enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to load files'), { variant: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  const loadAgents = async () => {
    try {
      const data = await AgentService.getAgents();
      setAgents(data);
    } catch (error) {
      enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to load agents'), { variant: 'error' });
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file || !selectedFile?.agent) return;

    setUploading(true);
    setUploadProgress(0);

    try {
      await AgentService.uploadFile(
        selectedFile.agent.uuid,
        file,
        (progress) => {
          setUploadProgress(progress);
        }
      );

      enqueueSnackbar('File uploaded successfully', { variant: 'success' });
      setUploadDialogOpen(false);
      loadFiles();
    } catch (error) {
      enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to upload file'), { variant: 'error' });
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const handleFileDownload = async (file) => {
    try {
      const response = await AgentService.downloadFile(file.id);
      const blob = new Blob([response.data]);
      saveAs(blob, file.filename);
      enqueueSnackbar('File download started', { variant: 'success' });
    } catch (error) {
      enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to download file'), { variant: 'error' });
    }
  };

  const handleFileDelete = async () => {
    if (!selectedFile) return;

    try {
      await AgentService.deleteFile(selectedFile.id);
      enqueueSnackbar('File deleted successfully', { variant: 'success' });
      setDeleteDialogOpen(false);
      loadFiles();
    } catch (error) {
      enqueueSnackbar(AgentService.getErrorMessage(error, 'Failed to delete file'), { variant: 'error' });
    }
  };

  const handleViewFile = async (file) => {
    setSelectedFile(file);
    setViewDialogOpen(true);
  };

  const filteredFiles = files.filter(file => {
    const matchesSearch = 
      file.filename?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      file.md5_hash?.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesAgent = filterAgent === 'all' || 
      (file.agent && file.agent.uuid === filterAgent);
    
    return matchesSearch && matchesAgent;
  });

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const UploadDialog = () => (
    <Dialog
      open={uploadDialogOpen}
      onClose={() => setUploadDialogOpen(false)}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>Upload File to Agent</DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          {selectedFile?.agent ? (
            <>
              <Alert severity="info" sx={{ mb: 2 }}>
                Uploading to: <strong>{selectedFile.agent.hostname}</strong>
              </Alert>
              
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Select Agent</InputLabel>
                <Select
                  value={selectedFile.agent.uuid}
                  onChange={(e) => {
                    const agent = agents.find(a => a.uuid === e.target.value);
                    setSelectedFile({ ...selectedFile, agent });
                  }}
                  label="Select Agent"
                >
                  {agents.map((agent) => (
                    <MenuItem key={agent.uuid} value={agent.uuid}>
                      {agent.hostname} ({agent.username})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              {uploading ? (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="body2" gutterBottom>
                    Uploading... {uploadProgress}%
                  </Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={uploadProgress} 
                  />
                </Box>
              ) : (
                <Button
                  variant="contained"
                  component="label"
                  fullWidth
                  startIcon={<UploadIcon />}
                >
                  Select File to Upload
                  <input
                    type="file"
                    hidden
                    onChange={handleFileUpload}
                  />
                </Button>
              )}
            </>
          ) : (
            <Alert severity="warning">
              Please select an agent first
            </Alert>
          )}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setUploadDialogOpen(false)}>Cancel</Button>
      </DialogActions>
    </Dialog>
  );

  const ViewDialog = () => (
    <Dialog
      open={viewDialogOpen}
      onClose={() => setViewDialogOpen(false)}
      maxWidth="md"
      fullWidth
    >
      <DialogTitle>
        File Details: {selectedFile?.filename}
      </DialogTitle>
      <DialogContent>
        {selectedFile && (
          <Box sx={{ mt: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  File Information
                </Typography>
                <Box sx={{ '& > *': { mb: 1 } }}>
                  <Box display="flex" justifyContent="space-between">
                    <Typography color="textSecondary">Filename:</Typography>
                    <Typography>{selectedFile.filename}</Typography>
                  </Box>
                  <Box display="flex" justifyContent="space-between">
                    <Typography color="textSecondary">Size:</Typography>
                    <Typography>{formatFileSize(selectedFile.file_size)}</Typography>
                  </Box>
                  <Box display="flex" justifyContent="space-between">
                    <Typography color="textSecondary">MD5:</Typography>
                    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                      {selectedFile.md5_hash}
                    </Typography>
                  </Box>
                  <Box display="flex" justifyContent="space-between">
                    <Typography color="textSecondary">Uploaded:</Typography>
                    <Typography>
                      {formatDistanceToNow(new Date(selectedFile.uploaded_at), { addSuffix: true })}
                    </Typography>
                  </Box>
                </Box>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Agent Information
                </Typography>
                {selectedFile.agent ? (
                  <Box sx={{ '& > *': { mb: 1 } }}>
                    <Box display="flex" justifyContent="space-between">
                      <Typography color="textSecondary">Hostname:</Typography>
                      <Typography>{selectedFile.agent.hostname}</Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography color="textSecondary">Username:</Typography>
                      <Typography>{selectedFile.agent.username}</Typography>
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography color="textSecondary">OS:</Typography>
                      <Typography>{selectedFile.agent.os}</Typography>
                    </Box>
                  </Box>
                ) : (
                  <Typography color="textSecondary">Agent information not available</Typography>
                )}
              </Grid>
            </Grid>
            
            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Actions
              </Typography>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <Button
                  variant="contained"
                  startIcon={<DownloadIcon />}
                  onClick={() => handleFileDownload(selectedFile)}
                >
                  Download
                </Button>
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<DeleteIcon />}
                  onClick={() => {
                    setViewDialogOpen(false);
                    setDeleteDialogOpen(true);
                  }}
                >
                  Delete
                </Button>
              </Box>
            </Box>
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setViewDialogOpen(false)}>Close</Button>
      </DialogActions>
    </Dialog>
  );

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" fontWeight="bold">
          File Manager
        </Typography>
        <Box display="flex" alignItems="center" gap={2}>
          <Button
            variant="contained"
            startIcon={<UploadIcon />}
            onClick={() => {
              setSelectedFile({ agent: agents[0] });
              setUploadDialogOpen(true);
            }}
            disabled={agents.length === 0}
          >
            Upload File
          </Button>
          <Tooltip title="Refresh">
            <IconButton onClick={loadFiles} disabled={isLoading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Filters */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              placeholder="Search files..."
              variant="outlined"
              size="small"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <FormControl fullWidth size="small">
              <InputLabel>Filter by Agent</InputLabel>
              <Select
                value={filterAgent}
                label="Filter by Agent"
                onChange={(e) => setFilterAgent(e.target.value)}
              >
                <MenuItem value="all">All Agents</MenuItem>
                {agents.map((agent) => (
                  <MenuItem key={agent.uuid} value={agent.uuid}>
                    {agent.hostname}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={2}>
            <Button
              fullWidth
              variant="outlined"
              onClick={() => {
                setSearchTerm('');
                setFilterAgent('all');
                setSelectedFiles([]);
              }}
            >
              Clear Filters
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Files Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell width="50px"></TableCell>
              <TableCell>Filename</TableCell>
              <TableCell>Size</TableCell>
              <TableCell>MD5 Hash</TableCell>
              <TableCell>Agent</TableCell>
              <TableCell>Uploaded</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7}>
                  <LinearProgress />
                </TableCell>
              </TableRow>
            ) : filteredFiles.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7}>
                  <Alert severity="info">
                    No files found. Upload files from the agent or use the upload button.
                  </Alert>
                </TableCell>
              </TableRow>
            ) : (
              filteredFiles.map((file) => (
                <TableRow key={file.id} hover>
                  <TableCell>
                    <FileIcon color="primary" />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                      {file.filename}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={formatFileSize(file.file_size)}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    <Tooltip title={file.md5_hash}>
                      <Typography
                        variant="caption"
                        sx={{
                          fontFamily: 'monospace',
                          display: 'block',
                          maxWidth: 100,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {file.md5_hash?.substring(0, 12)}...
                      </Typography>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    {file.agent ? (
                      <Chip
                        label={file.agent.hostname}
                        size="small"
                        icon={<FolderIcon />}
                      />
                    ) : (
                      <Typography variant="caption" color="textSecondary">
                        Unknown
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <ScheduleIcon fontSize="small" />
                      <Typography variant="body2">
                        {formatDistanceToNow(new Date(file.uploaded_at), { addSuffix: true })}
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Download">
                      <IconButton
                        size="small"
                        onClick={() => handleFileDownload(file)}
                      >
                        <DownloadIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="View Details">
                      <IconButton
                        size="small"
                        onClick={() => handleViewFile(file)}
                      >
                        <ViewIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        setAnchorEl(e.currentTarget);
                        setSelectedFile(file);
                      }}
                    >
                      <MoreVertIcon fontSize="small" />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between' }}>
        <Typography variant="body2" color="textSecondary">
          {filteredFiles.length} files found
        </Typography>
        {selectedFiles.length > 0 && (
          <Box display="flex" gap={1}>
            <Button
              size="small"
              variant="outlined"
              startIcon={<DownloadIcon />}
            >
              Download Selected ({selectedFiles.length})
            </Button>
            <Button
              size="small"
              variant="outlined"
              color="error"
              startIcon={<DeleteIcon />}
            >
              Delete Selected
            </Button>
          </Box>
        )}
      </Box>

      {/* Dialogs */}
      <UploadDialog />
      <ViewDialog />

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <DialogTitle>Delete File</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete "{selectedFile?.filename}"?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleFileDelete} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        <MenuItem onClick={() => {
          handleFileDownload(selectedFile);
          setAnchorEl(null);
        }}>
          <DownloadIcon fontSize="small" sx={{ mr: 1 }} /> Download
        </MenuItem>
        <MenuItem onClick={() => {
          handleViewFile(selectedFile);
          setAnchorEl(null);
        }}>
          <ViewIcon fontSize="small" sx={{ mr: 1 }} /> View Details
        </MenuItem>
        <MenuItem onClick={() => {
          setAnchorEl(null);
          setDeleteDialogOpen(true);
        }} sx={{ color: 'error.main' }}>
          <DeleteIcon fontSize="small" sx={{ mr: 1 }} /> Delete
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default FileManager;
