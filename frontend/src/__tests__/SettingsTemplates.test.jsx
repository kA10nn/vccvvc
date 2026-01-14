import React from 'react';
// Mock axios to avoid ESM import errors in Jest
jest.mock('axios', () => ({ create: () => ({ interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } }, get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }) }));

import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Settings from '../pages/Settings';

// mock notistack to avoid runtime errors from enqueueSnackbar
jest.mock('notistack', () => ({ enqueueSnackbar: jest.fn() }));
import SettingsService from '../services/settingsService';

jest.mock('../services/settingsService');

describe('Settings command templates UI', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    SettingsService.getSettings = jest.fn().mockResolvedValue({});
  });

  test('edit template opens dialog and saves via API', async () => {
    const tmpl = { id: 5, name: 'Old', value: 'cmd', template: '-v', created_by: 'system', description: '' };
    SettingsService.getCommandTemplates.mockResolvedValue([tmpl]);
    SettingsService.updateCommandTemplate.mockImplementation((id, data) => Promise.resolve({ ...data, id }));

    render(<Settings />);

    await waitFor(() => expect(SettingsService.getCommandTemplates).toHaveBeenCalled());

    // Open the Command Templates tab
    const commandTab = screen.getByRole('tab', { name: /command templates/i });
    userEvent.click(commandTab);

    // Click edit button within the template's row
    const row = await screen.findByText('Old').then(el => el.closest('tr'));
    const editButton = within(row).getAllByRole('button')[0];
    userEvent.click(editButton);

    // Dialog should open with fields
    const nameInput = await screen.findByLabelText(/Name/);
    expect(nameInput).toBeTruthy();

    // change name
    userEvent.clear(nameInput);
    userEvent.type(nameInput, 'NewName');

    // click Save
    const save = screen.getByRole('button', { name: /save/i });
    userEvent.click(save);

    await waitFor(() => expect(SettingsService.updateCommandTemplate).toHaveBeenCalledWith(5, expect.objectContaining({ name: 'NewName' })));

    // ensure table updated
    expect(await screen.findByText('NewName')).toBeTruthy();
  });
});