import { createSlice } from '@reduxjs/toolkit';

const taskSlice = createSlice({
  name: 'tasks',
  initialState: {
    items: [],
  },
  reducers: {
    setTasks: (state, action) => {
      state.items = action.payload;
    },
    addTask: (state, action) => {
      state.items.unshift(action.payload);
    },
    updateTask: (state, action) => {
      const payload = action.payload || {};
      const taskId = payload.id ?? payload.task_id;
      if (!taskId) return;
      state.items = state.items.map((task) =>
        task.id === taskId ? { ...task, ...payload } : task
      );
    },
    clearTasks: (state) => {
      state.items = [];
    },
  },
});

export const { setTasks, addTask, updateTask, clearTasks } = taskSlice.actions;
export default taskSlice.reducer;
