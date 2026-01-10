import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import agentService from '../services/agentService';

export const fetchAgents = createAsyncThunk(
  'agents/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      return await agentService.getAgents();
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const fetchAgent = createAsyncThunk(
  'agents/fetchOne',
  async (agentId, { rejectWithValue }) => {
    try {
      return await agentService.getAgent(agentId);
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const createTask = createAsyncThunk(
  'agents/createTask',
  async ({ agentId, command, args }, { rejectWithValue }) => {
    try {
      return await agentService.createTask(agentId, command, args);
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

export const deleteAgent = createAsyncThunk(
  'agents/delete',
  async (agentId, { rejectWithValue }) => {
    try {
      await agentService.deleteAgent(agentId);
      return agentId;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

const agentSlice = createSlice({
  name: 'agents',
  initialState: {
    agents: [],
    selectedAgent: null,
    isLoading: false,
    error: null,
  },
  reducers: {
    setSelectedAgent: (state, action) => {
      state.selectedAgent = action.payload;
    },
    addAgent: (state, action) => {
      const existingIndex = state.agents.findIndex(a => a.uuid === action.payload.uuid);
      if (existingIndex >= 0) {
        state.agents[existingIndex] = action.payload;
      } else {
        state.agents.push(action.payload);
      }
    },
    updateAgentStatus: (state, action) => {
      const { uuid, status } = action.payload;
      const agent = state.agents.find(a => a.uuid === uuid);
      if (agent) {
        agent.status = status;
        agent.last_seen = new Date().toISOString();
      }
    },
    clearAgents: (state) => {
      state.agents = [];
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchAgents.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchAgents.fulfilled, (state, action) => {
        state.isLoading = false;
        state.agents = action.payload;
      })
      .addCase(fetchAgents.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      .addCase(deleteAgent.fulfilled, (state, action) => {
        state.agents = state.agents.filter(agent => agent.uuid !== action.payload);
      });
  },
});

export const { setSelectedAgent, addAgent, updateAgentStatus, clearAgents } = agentSlice.actions;
export default agentSlice.reducer;
