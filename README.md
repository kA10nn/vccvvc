ARES C2 — repo notes

Persistent command templates

- New endpoints to store and manage reusable command templates (aka scripts) on the server:
  - GET /api/v1/settings/command-templates — list templates (requires auth)
  - POST /api/v1/settings/command-templates — create template (requires auth)
  - DELETE /api/v1/settings/command-templates/{id} — delete template (requires auth)

This avoids using localStorage for custom commands and ensures templates persist across clients and are available in the Task Creator UI. Local templates stored under `ares_custom_commands` will be migrated to server-side templates automatically on first open of the Task Creator.
