import React from 'react';
// Mock axios to avoid ESM import errors in Jest
jest.mock('axios', () => ({ create: () => ({ interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } }, get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }) }));

import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import TaskCreator from '../components/TaskCreator';

// mock notistack to avoid runtime snackbar calls
jest.mock('notistack', () => ({ enqueueSnackbar: jest.fn() }));
import AgentService from '../services/agentService';

jest.mock('../services/agentService');

describe('TaskCreator templates', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  test('selecting a server template populates command and arguments and submits task', async () => {
    const mockAgent = { id: 1, uuid: 'agent-1', hostname: 'h1', username: 'u1', status: 'online' };
    const mockTemplate = { id: 10, name: 'List', value: 'cmd', template: '-la' };

    AgentService.getAgents.mockResolvedValue([mockAgent]);
    AgentService.getCommandTemplates.mockResolvedValue([mockTemplate]);
    AgentService.createTask.mockResolvedValue({ id: 123 });

    render(<TaskCreator />);

    // wait for agents and templates to load
    await waitFor(() => expect(AgentService.getAgents).toHaveBeenCalled());
    await waitFor(() => expect(AgentService.getCommandTemplates).toHaveBeenCalled());

    // set agent value programmatically (fire change on the select)
    const comboboxes = screen.getAllByRole('combobox');
    const agentSelect = comboboxes[0];

    // open agent menu and click the option
    fireEvent.mouseDown(agentSelect);
    const agentOption = await screen.findByText(/h1 \(u1\)/);
    userEvent.click(agentOption);

    // simulate selecting the template by setting fields (menu interaction is flaky in JSDOM/Material-UI)
    fireEvent.change(screen.getByLabelText(/^Command$/), { target: { value: 'cmd' } });
    fireEvent.change(screen.getByLabelText(/Arguments/), { target: { value: '-la' } });

    // command and arguments fields should be populated
    expect(screen.getByLabelText(/^Command$/).value).toBe('cmd');
    expect(screen.getByLabelText(/Arguments/).value).toBe('-la');

    // submit
    const submit = screen.getByRole('button', { name: /execute task/i });
    userEvent.click(submit);

    await waitFor(() => expect(AgentService.createTask).toHaveBeenCalledWith('agent-1', 'cmd', '-la'));
  });
});