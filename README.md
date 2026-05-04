# ChatGPT Docs MCP

A small remote MCP server for ChatGPT official Web. It gives ChatGPT a simple Markdown-oriented workspace backed by local files.

The service exposes MCP tools for listing, reading, searching, writing, patching, moving, and trashing text files. It is designed for personal use with ChatGPT Developer Mode, OAuth, and Cloudflare Tunnel.

## What It Runs

```text
ChatGPT
  -> https://your-mcp-domain.example.com
  -> Cloudflare Tunnel
  -> chatgpt-docs-mcp:8787
  -> data/docs
```

The MCP server is a Node.js app in `src/server.js`. Docker is used only to make deployment and isolation easy.

## Features

- Remote MCP over Streamable HTTP
- OAuth authorization for ChatGPT
- Dynamic Client Registration (DCR)
- Markdown/text file workspace
- Path sandboxing under `data/docs`
- History backup before writes
- Trash instead of permanent delete
- Audit log for write operations
- Cloudflare Tunnel compose setup

## Files

```text
data/docs/              Files ChatGPT can read and write
data/history/           Backups created before overwrites or patches
data/trash/             Files moved by trash_file
data/audit.log          JSONL audit log for write operations
data/oauth-clients.json Dynamic OAuth clients registered by ChatGPT
```

Only `data/docs` is exposed as the document workspace. Paths are always relative to that directory.

## Requirements

- Docker and Docker Compose
- A Cloudflare Tunnel token
- A public hostname routed to this service, for example:

```text
https://your-mcp-domain.example.com
```

## Setup

Clone or copy this project, then create the runtime files:

```bash
cp .env.example .env
mkdir -p data/docs data/history data/trash
touch data/audit.log data/oauth-clients.json
chown -R 1000:1000 data
chmod -R 750 data
```

Generate secrets:

```bash
openssl rand -hex 32
openssl rand -hex 24
```

Edit `.env`:

```env
PUBLIC_BASE_URL=https://your-mcp-domain.example.com
OAUTH_CLIENT_ID=chatgpt
OAUTH_CLIENT_SECRET=<replace-with-random-hex>
ADMIN_PASSWORD=<replace-with-random-password>
CLOUDFLARED_TOKEN=<replace-with-cloudflare-tunnel-token>
```

The real `.env` file is ignored by git. Do not commit it.

## Cloudflare Tunnel

In Cloudflare Zero Trust, configure the tunnel public hostname:

```text
Public hostname:
your-mcp-domain.example.com

Service:
http://chatgpt-docs-mcp:8787
```

Start the service:

```bash
docker compose up -d --build
```

Check logs:

```bash
docker logs --tail 80 chatgpt-docs-mcp
docker logs --tail 80 chatgpt-docs-mcp-tunnel
```

## ChatGPT Setup

In ChatGPT official Web, create a connector/app from a remote MCP server.

Use:

```text
MCP Server URL:
https://your-mcp-domain.example.com/mcp
```

OAuth settings:

```text
Registration method:
Dynamic Client Registration (DCR)

Token endpoint auth method:
none

Default scopes:
files:read
files:write

Base scopes:
leave empty
```

When ChatGPT opens the authorization page, enter the value of `ADMIN_PASSWORD`.

The server also accepts MCP requests at `/` for compatibility with clients that ignore the `/mcp` path.

## Tools

- `list_files`
- `read_file`
- `read_many_files`
- `search_files`
- `write_file`
- `append_file`
- `patch_file`
- `move_file`
- `trash_file`
- `delete_empty_directory`
- `get_file_info`

## Safety Notes

- The container runs as UID/GID `1000:1000`.
- The container filesystem is read-only except mounted data paths.
- Linux capabilities are dropped.
- `no-new-privileges` is enabled.
- Dot-directories and path traversal are blocked.
- File extensions are restricted to common text formats.
- `trash_file` moves files to `data/trash`; it falls back to copy and unlink across filesystems.
- `delete_empty_directory` only removes empty directories.

## Development

Run locally without Docker:

```bash
npm install
cp .env.example .env
node src/server.js
```

Local HTTP is fine for development, but ChatGPT remote MCP requires a public HTTPS URL.
