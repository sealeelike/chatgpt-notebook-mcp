# Runtime Data

Create these directories and files before running the service:

```bash
mkdir -p data/docs data/history data/trash
touch data/audit.log data/oauth-clients.json
chown -R 1000:1000 data
chmod -R 750 data
```

The `data/` directory itself is ignored by git because it contains private documents, OAuth clients, audit logs, history, and trash.
