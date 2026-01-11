import React from 'react';
import { Box } from '@mui/material';
import TaskCreator from '../components/TaskCreator';

const Tasks = () => (
  <Box sx={{ flexGrow: 1, p: 3 }}>
    <TaskCreator />
  </Box>
);

export default Tasks;
