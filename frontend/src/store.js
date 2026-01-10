import { configureStore } from '@reduxjs/toolkit';
import authReducer from './store/authSlice';
import agentReducer from './store/agentSlice';
import taskReducer from './store/taskSlice';
import uiReducer from './store/uiSlice';

const store = configureStore({
  reducer: {
    auth: authReducer,
    agents: agentReducer,
    tasks: taskReducer,
    ui: uiReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['websocket/connect', 'websocket/message'],
        ignoredPaths: ['websocket.connection'],
      },
    }),
  devTools: process.env.NODE_ENV !== 'production',
});

export default store;
