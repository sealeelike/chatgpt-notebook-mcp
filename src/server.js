import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import cookieParser from "cookie-parser";
import express from "express";
import { z } from "zod";

const config = {
  publicBaseUrl: mustEnv("PUBLIC_BASE_URL").replace(/\/+$/, ""),
  port: Number(process.env.PORT || "8787"),
  clientId: mustEnv("OAUTH_CLIENT_ID"),
  clientSecret: mustEnv("OAUTH_CLIENT_SECRET"),
  adminPassword: mustEnv("ADMIN_PASSWORD"),
  allowedRedirectUris: (process.env.ALLOWED_REDIRECT_URIS || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean),
  accessTokenTtlSeconds: Number(process.env.ACCESS_TOKEN_TTL_SECONDS || "3600"),
  authCodeTtlSeconds: Number(process.env.AUTH_CODE_TTL_SECONDS || "300"),
  maxFileBytes: Number(process.env.MAX_FILE_BYTES || String(1024 * 1024)),
  maxSearchResults: Number(process.env.MAX_SEARCH_RESULTS || "50"),
  docsRoot: process.env.DOCS_ROOT || "/data/docs",
  historyRoot: process.env.HISTORY_ROOT || "/data/history",
  trashRoot: process.env.TRASH_ROOT || "/data/trash",
  auditLog: process.env.AUDIT_LOG || "/data/audit.log",
  oauthClientsFile: process.env.OAUTH_CLIENTS_FILE || "/data/oauth-clients.json",
};

const blockedSegments = new Set(["", ".", "..", ".git", ".ssh", ".env", ".obsidian", ".trash"]);
const textExtensions = new Set([
  ".md",
  ".markdown",
  ".txt",
  ".json",
  ".jsonl",
  ".yaml",
  ".yml",
  ".csv",
  ".tsv",
  ".log",
]);

const authCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();
const oauthClients = new Map();
const transports = {};

oauthClients.set(config.clientId, {
  clientId: config.clientId,
  clientSecret: config.clientSecret,
  redirectUris: [],
  tokenEndpointAuthMethod: "client_secret_post",
  dynamic: false,
});

await ensureDir(config.docsRoot);
await ensureDir(config.historyRoot);
await ensureDir(config.trashRoot);
await ensureFile(config.auditLog);
await ensureFile(config.oauthClientsFile);
await loadOauthClients();

const app = express();
app.disable("x-powered-by");
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "2mb" }));
app.use((req, res, next) => {
  const startedAt = Date.now();
  res.on("finish", () => {
    console.log(
      JSON.stringify({
        time: new Date().toISOString(),
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration_ms: Date.now() - startedAt,
        user_agent: req.get("user-agent") || "",
      })
    );
  });
  next();
});
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Authorization,Content-Type,Mcp-Session-Id,MCP-Protocol-Version"
  );
  res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
});

app.get("/", (_req, res) => {
  res.type("text/plain").send("chatgpt-docs-mcp\n");
});

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/.well-known/oauth-authorization-server", (_req, res) => {
  const base = config.publicBaseUrl;
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["files:read", "files:write"],
  });
});

app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json(protectedResourceMetadata());
});

app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => {
  res.json(protectedResourceMetadata());
});

app.post("/oauth/register", (req, res) => {
  const body = req.body || {};
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.map(String) : [];
  if (redirectUris.length === 0 || !redirectUris.every(isAllowedRedirectUri)) {
    res.status(400).json({ error: "invalid_redirect_uri" });
    return;
  }

  const requestedMethod = String(body.token_endpoint_auth_method || "none");
  const method = ["none", "client_secret_post", "client_secret_basic"].includes(requestedMethod)
    ? requestedMethod
    : "none";
  const clientId = `chatgpt-${randomToken().slice(0, 24)}`;
  const clientSecret = method === "none" ? undefined : randomToken();
  oauthClients.set(clientId, {
    clientId,
    clientSecret,
    redirectUris,
    tokenEndpointAuthMethod: method,
    dynamic: true,
  });
  saveOauthClients().catch((error) => console.error("failed to save oauth clients", error));

  const response = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    token_endpoint_auth_method: method,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    redirect_uris: redirectUris,
  };
  if (clientSecret) {
    response.client_secret = clientSecret;
    response.client_secret_expires_at = 0;
  }
  res.status(201).json({
    ...response,
  });
});

app.get("/oauth/authorize", (req, res) => {
  const validation = validateAuthorizeQuery(req.query);
  if (!validation.ok) {
    res.status(400).type("text/plain").send(validation.error);
    return;
  }

  res.type("html").send(renderAuthorizePage(req.query));
});

app.post("/oauth/authorize", (req, res) => {
  const validation = validateAuthorizeQuery(req.body);
  if (!validation.ok) {
    res.status(400).type("text/plain").send(validation.error);
    return;
  }

  if (!constantTimeEqual(String(req.body.password || ""), config.adminPassword)) {
    res.status(401).type("html").send(renderAuthorizePage(req.body, "Invalid password."));
    return;
  }

  const code = randomToken();
  authCodes.set(code, {
    clientId: String(req.body.client_id),
    redirectUri: String(req.body.redirect_uri),
    codeChallenge: req.body.code_challenge ? String(req.body.code_challenge) : "",
    codeChallengeMethod: req.body.code_challenge_method ? String(req.body.code_challenge_method) : "plain",
    expiresAt: Date.now() + config.authCodeTtlSeconds * 1000,
  });

  const redirect = new URL(String(req.body.redirect_uri));
  redirect.searchParams.set("code", code);
  if (req.body.state) {
    redirect.searchParams.set("state", String(req.body.state));
  }
  res.redirect(302, redirect.toString());
});

app.post("/oauth/token", (req, res) => {
  const body = req.body || {};
  const auth = parseClientAuth(req);
  if (!auth.ok) {
    res.status(401).json({ error: "invalid_client" });
    return;
  }

  if (body.grant_type === "authorization_code") {
    const codeRecord = authCodes.get(String(body.code || ""));
    if (!codeRecord || codeRecord.expiresAt < Date.now()) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }
    if (codeRecord.clientId !== auth.clientId || codeRecord.redirectUri !== String(body.redirect_uri || "")) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }
    if (!verifyPkce(codeRecord, String(body.code_verifier || ""))) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }
    authCodes.delete(String(body.code || ""));
    res.json(issueTokens(auth.clientId));
    return;
  }

  if (body.grant_type === "refresh_token") {
    const refreshRecord = refreshTokens.get(String(body.refresh_token || ""));
    if (!refreshRecord || refreshRecord.clientId !== auth.clientId) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }
    res.json(issueTokens(auth.clientId));
    return;
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

app.all(["/mcp", "/"], requireBearerToken, async (req, res) => {
  if (req.path === "/" && req.method === "GET") {
    res.type("text/plain").send("chatgpt-docs-mcp\n");
    return;
  }

  try {
    const sessionId = req.headers["mcp-session-id"];
    let transport;

    if (sessionId && transports[sessionId]) {
      transport = transports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
        onsessioninitialized: (newSessionId) => {
          transports[newSessionId] = transport;
        },
      });
      transport.onclose = () => {
        if (transport.sessionId) {
          delete transports[transport.sessionId];
        }
      };
      const server = createMcpServer();
      await server.connect(transport);
    } else if (req.method === "GET") {
      res.status(405).json(jsonRpcError(null, -32000, "SSE stream requires an initialized session."));
      return;
    } else {
      res.status(400).json(jsonRpcError(null, -32000, "Bad or missing MCP session."));
      return;
    }

    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error(error);
    if (!res.headersSent) {
      res.status(500).json(jsonRpcError(null, -32603, "Internal server error."));
    }
  }
});

app.listen(config.port, "0.0.0.0", () => {
  console.log(`chatgpt-docs-mcp listening on ${config.port}`);
});

function createMcpServer() {
  const server = new McpServer({
    name: "chatgpt-docs-mcp",
    version: "0.1.0",
  });

  server.tool(
    "list_files",
    "List files and directories below a relative directory in the docs workspace. Use this before reading when you need to discover paths.",
    {
      path: z.string().default(".").describe("Relative directory path under the docs workspace."),
      recursive: z.boolean().default(false).describe("Whether to list nested files recursively."),
    },
    async ({ path: inputPath = ".", recursive = false }) => {
      const target = await resolveWorkspacePath(inputPath, { allowDirectory: true });
      const entries = await listEntries(target.absolutePath, target.relativePath, recursive);
      return textResult({ path: target.relativePath || ".", entries });
    }
  );

  server.tool(
    "read_file",
    "Read one text file from the docs workspace. Use this for Markdown notes and small text documents.",
    {
      path: z.string().describe("Relative file path under the docs workspace."),
    },
    async ({ path: inputPath }) => {
      const target = await resolveWorkspacePath(inputPath);
      await assertTextFile(target.absolutePath);
      const stat = await fs.stat(target.absolutePath);
      if (stat.size > config.maxFileBytes) {
        throw new Error(`File is too large: ${stat.size} bytes.`);
      }
      const content = await fs.readFile(target.absolutePath, "utf8");
      return textResult({ path: target.relativePath, size: stat.size, content });
    }
  );

  server.tool(
    "read_many_files",
    "Read several text files from the docs workspace in one call.",
    {
      paths: z.array(z.string()).min(1).max(20).describe("Relative file paths under the docs workspace."),
    },
    async ({ paths }) => {
      const files = [];
      for (const inputPath of paths) {
        const target = await resolveWorkspacePath(inputPath);
        await assertTextFile(target.absolutePath);
        const stat = await fs.stat(target.absolutePath);
        if (stat.size > config.maxFileBytes) {
          files.push({ path: target.relativePath, error: `File is too large: ${stat.size} bytes.` });
          continue;
        }
        files.push({
          path: target.relativePath,
          size: stat.size,
          content: await fs.readFile(target.absolutePath, "utf8"),
        });
      }
      return textResult({ files });
    }
  );

  server.tool(
    "search_files",
    "Search text files by substring. Use this to find notes before reading or editing them.",
    {
      query: z.string().min(1).describe("Case-insensitive text query."),
      path: z.string().default(".").describe("Relative directory to search under."),
      max_results: z.number().int().min(1).max(100).default(config.maxSearchResults),
    },
    async ({ query, path: inputPath = ".", max_results = config.maxSearchResults }) => {
      const target = await resolveWorkspacePath(inputPath, { allowDirectory: true });
      const results = await searchFiles(target.absolutePath, target.relativePath, query, max_results);
      return textResult({ query, results });
    }
  );

  server.tool(
    "write_file",
    "Create or overwrite a text file. Existing files are backed up to history first. Use append_file or patch_file for safer edits when possible.",
    {
      path: z.string().describe("Relative file path under the docs workspace."),
      content: z.string().describe("Complete file content to write."),
    },
    async ({ path: inputPath, content }) => {
      const target = await resolveWorkspacePath(inputPath, { mustExist: false });
      await assertTextPath(target.absolutePath);
      await ensureParent(target.absolutePath);
      await backupIfExists(target.absolutePath, target.relativePath);
      await fs.writeFile(target.absolutePath, content, "utf8");
      await audit("write_file", { path: target.relativePath, bytes: Buffer.byteLength(content) });
      return textResult({ ok: true, path: target.relativePath });
    }
  );

  server.tool(
    "append_file",
    "Append text to a file, creating it if needed. Useful for inbox notes, logs, and daily notes.",
    {
      path: z.string().describe("Relative file path under the docs workspace."),
      content: z.string().describe("Text to append."),
    },
    async ({ path: inputPath, content }) => {
      const target = await resolveWorkspacePath(inputPath, { mustExist: false });
      await assertTextPath(target.absolutePath);
      await ensureParent(target.absolutePath);
      await backupIfExists(target.absolutePath, target.relativePath);
      await fs.appendFile(target.absolutePath, content, "utf8");
      await audit("append_file", { path: target.relativePath, bytes: Buffer.byteLength(content) });
      return textResult({ ok: true, path: target.relativePath });
    }
  );

  server.tool(
    "patch_file",
    "Replace exact text within a file. This is safer than overwriting a full document. Fails when old_text is not found.",
    {
      path: z.string().describe("Relative file path under the docs workspace."),
      old_text: z.string().min(1).describe("Exact text to replace."),
      new_text: z.string().describe("Replacement text."),
      replace_all: z.boolean().default(false).describe("Replace every occurrence instead of only the first."),
    },
    async ({ path: inputPath, old_text, new_text, replace_all = false }) => {
      const target = await resolveWorkspacePath(inputPath);
      await assertTextFile(target.absolutePath);
      const content = await fs.readFile(target.absolutePath, "utf8");
      if (!content.includes(old_text)) {
        throw new Error("old_text was not found.");
      }
      const updated = replace_all ? content.split(old_text).join(new_text) : content.replace(old_text, new_text);
      await backupIfExists(target.absolutePath, target.relativePath);
      await fs.writeFile(target.absolutePath, updated, "utf8");
      await audit("patch_file", { path: target.relativePath, replace_all });
      return textResult({ ok: true, path: target.relativePath });
    }
  );

  server.tool(
    "move_file",
    "Move or rename a file within the docs workspace. The destination parent directory is created if needed.",
    {
      from: z.string().describe("Existing relative file path."),
      to: z.string().describe("New relative file path."),
    },
    async ({ from, to }) => {
      const source = await resolveWorkspacePath(from);
      const destination = await resolveWorkspacePath(to, { mustExist: false });
      await assertTextPath(destination.absolutePath);
      await ensureParent(destination.absolutePath);
      await backupIfExists(source.absolutePath, source.relativePath);
      await fs.rename(source.absolutePath, destination.absolutePath);
      await audit("move_file", { from: source.relativePath, to: destination.relativePath });
      return textResult({ ok: true, from: source.relativePath, to: destination.relativePath });
    }
  );

  server.tool(
    "trash_file",
    "Move a file to the trash directory instead of permanently deleting it.",
    {
      path: z.string().describe("Relative file path under the docs workspace."),
    },
    async ({ path: inputPath }) => {
      const target = await resolveWorkspacePath(inputPath);
      const trashPath = path.join(config.trashRoot, `${timestamp()}__${target.relativePath.replaceAll("/", "__")}`);
      await ensureParent(trashPath);
      await moveAcrossDevices(target.absolutePath, trashPath);
      await audit("trash_file", { path: target.relativePath, trash_path: trashPath });
      return textResult({ ok: true, path: target.relativePath });
    }
  );

  server.tool(
    "delete_empty_directory",
    "Delete an empty directory within the docs workspace. This only removes empty directories and never deletes files recursively.",
    {
      path: z.string().describe("Relative empty directory path under the docs workspace."),
    },
    async ({ path: inputPath }) => {
      const target = await resolveWorkspacePath(inputPath, { allowDirectory: true });
      if (!target.relativePath) {
        throw new Error("Refusing to delete the docs workspace root.");
      }
      const stat = await fs.stat(target.absolutePath);
      if (!stat.isDirectory()) {
        throw new Error("Path is not a directory.");
      }
      await fs.rmdir(target.absolutePath);
      await audit("delete_empty_directory", { path: target.relativePath });
      return textResult({ ok: true, path: target.relativePath });
    }
  );

  server.tool(
    "get_file_info",
    "Get metadata for a file or directory in the docs workspace.",
    {
      path: z.string().describe("Relative path under the docs workspace."),
    },
    async ({ path: inputPath }) => {
      const target = await resolveWorkspacePath(inputPath, { allowDirectory: true });
      const stat = await fs.stat(target.absolutePath);
      return textResult({
        path: target.relativePath || ".",
        type: stat.isDirectory() ? "directory" : "file",
        size: stat.size,
        modified_at: stat.mtime.toISOString(),
        created_at: stat.birthtime.toISOString(),
      });
    }
  );

  return server;
}

function mustEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function protectedResourceMetadata() {
  return {
    resource: `${config.publicBaseUrl}/mcp`,
    authorization_servers: [config.publicBaseUrl],
    bearer_methods_supported: ["header"],
  };
}

function requireBearerToken(req, res, next) {
  const header = req.get("authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    res.setHeader("WWW-Authenticate", `Bearer resource_metadata="${config.publicBaseUrl}/.well-known/oauth-protected-resource/mcp"`);
    res.status(401).json({ error: "missing_bearer_token" });
    return;
  }
  const record = accessTokens.get(match[1]);
  if (!record || record.expiresAt < Date.now()) {
    res.status(401).json({ error: "invalid_or_expired_token" });
    return;
  }
  next();
}

function validateAuthorizeQuery(query) {
  if (query.response_type !== "code") return { ok: false, error: "response_type must be code" };
  const clientId = String(query.client_id || "");
  let client = oauthClients.get(clientId);
  if (!client && clientId.startsWith("chatgpt-") && query.redirect_uri && isAllowedRedirectUri(String(query.redirect_uri))) {
    client = {
      clientId,
      redirectUris: [String(query.redirect_uri)],
      tokenEndpointAuthMethod: "none",
      dynamic: true,
      recovered: true,
    };
    oauthClients.set(clientId, client);
    saveOauthClients().catch((error) => console.error("failed to save recovered oauth client", error));
  }
  if (!client) return { ok: false, error: "invalid client_id" };
  if (!query.redirect_uri || !isAllowedRedirectUri(String(query.redirect_uri))) {
    return { ok: false, error: "redirect_uri is not allowed" };
  }
  if (client.redirectUris.length > 0 && !client.redirectUris.includes(String(query.redirect_uri))) {
    return { ok: false, error: "redirect_uri is not registered for this client" };
  }
  if (query.code_challenge_method && query.code_challenge_method !== "S256") {
    return { ok: false, error: "code_challenge_method must be S256" };
  }
  if (!query.code_challenge) {
    return { ok: false, error: "code_challenge is required" };
  }
  return { ok: true };
}

function isAllowedRedirectUri(uri) {
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  if (config.allowedRedirectUris.length === 0) {
    return parsed.hostname === "chatgpt.com" || parsed.hostname === "chat.openai.com" || parsed.hostname.endsWith(".chatgpt.com");
  }
  return config.allowedRedirectUris.includes(uri);
}

async function loadOauthClients() {
  let raw = "";
  try {
    raw = await fs.readFile(config.oauthClientsFile, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (!raw.trim()) return;
  const clients = JSON.parse(raw);
  if (!Array.isArray(clients)) return;
  for (const client of clients) {
    if (!client || !client.clientId || client.clientId === config.clientId) continue;
    oauthClients.set(client.clientId, {
      clientId: String(client.clientId),
      clientSecret: client.clientSecret ? String(client.clientSecret) : undefined,
      redirectUris: Array.isArray(client.redirectUris) ? client.redirectUris.map(String) : [],
      tokenEndpointAuthMethod: String(client.tokenEndpointAuthMethod || "none"),
      dynamic: true,
      recovered: Boolean(client.recovered),
    });
  }
}

async function saveOauthClients() {
  const clients = [...oauthClients.values()]
    .filter((client) => client.dynamic)
    .map((client) => ({
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUris: client.redirectUris,
      tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
      recovered: Boolean(client.recovered),
    }));
  await fs.writeFile(config.oauthClientsFile, `${JSON.stringify(clients, null, 2)}\n`, "utf8");
}

function parseClientAuth(req) {
  let clientId = req.body.client_id;
  let clientSecret = req.body.client_secret;
  const auth = req.get("authorization") || "";
  if (auth.startsWith("Basic ")) {
    const decoded = Buffer.from(auth.slice("Basic ".length), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator !== -1) {
      clientId = decoded.slice(0, separator);
      clientSecret = decoded.slice(separator + 1);
    }
  }
  const client = oauthClients.get(String(clientId || ""));
  if (!client) return { ok: false };
  if (client.tokenEndpointAuthMethod === "none") {
    return { ok: true, clientId: client.clientId };
  }
  const ok = Boolean(client.clientSecret) && constantTimeEqual(String(clientSecret || ""), client.clientSecret);
  return ok ? { ok: true, clientId: client.clientId } : { ok: false };
}

function issueTokens(clientId) {
  const accessToken = randomToken();
  const refreshToken = randomToken();
  accessTokens.set(accessToken, {
    clientId,
    expiresAt: Date.now() + config.accessTokenTtlSeconds * 1000,
  });
  refreshTokens.set(refreshToken, { clientId });
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: config.accessTokenTtlSeconds,
    refresh_token: refreshToken,
  };
}

function verifyPkce(codeRecord, verifier) {
  if (!codeRecord.codeChallenge) return true;
  if (!verifier) return false;
  if (codeRecord.codeChallengeMethod === "S256") {
    const digest = crypto.createHash("sha256").update(verifier).digest("base64url");
    return digest === codeRecord.codeChallenge;
  }
  return verifier === codeRecord.codeChallenge;
}

function renderAuthorizePage(query, error = "") {
  const hidden = ["response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method"]
    .map((key) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(String(query[key] || ""))}">`)
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize ChatGPT Docs MCP</title>
  <style>
    body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f6f7f9;color:#111827}
    main{max-width:420px;margin:12vh auto;padding:28px;background:#fff;border:1px solid #e5e7eb;border-radius:8px}
    label{display:block;font-weight:600;margin:18px 0 8px}
    input[type=password]{width:100%;box-sizing:border-box;padding:12px;border:1px solid #cbd5e1;border-radius:6px}
    button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:6px;background:#111827;color:#fff;font-weight:700}
    .error{color:#b91c1c;margin:12px 0}
    p{line-height:1.5;color:#4b5563}
  </style>
</head>
<body>
  <main>
    <h1>Authorize Docs MCP</h1>
    <p>Allow ChatGPT to read and write the configured Markdown workspace.</p>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
    <form method="post" action="/oauth/authorize">
      ${hidden}
      <label for="password">Admin password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button type="submit">Authorize</button>
    </form>
  </main>
</body>
</html>`;
}

async function resolveWorkspacePath(inputPath, options = {}) {
  const relative = normalizeRelativePath(inputPath);
  const absolutePath = path.resolve(config.docsRoot, relative);
  const root = path.resolve(config.docsRoot);
  if (absolutePath !== root && !absolutePath.startsWith(`${root}${path.sep}`)) {
    throw new Error("Path escapes docs workspace.");
  }
  if (options.mustExist !== false) {
    const stat = await fs.stat(absolutePath);
    if (!options.allowDirectory && stat.isDirectory()) {
      throw new Error("Expected a file path, got a directory.");
    }
  }
  return { relativePath: relative, absolutePath };
}

function normalizeRelativePath(inputPath) {
  const raw = String(inputPath || ".").replaceAll("\\", "/");
  const normalized = path.posix.normalize(raw).replace(/^\/+/, "");
  const parts = normalized === "." ? [] : normalized.split("/");
  for (const part of parts) {
    if (blockedSegments.has(part) || part.startsWith(".")) {
      throw new Error(`Blocked path segment: ${part}`);
    }
  }
  return parts.join("/");
}

async function assertTextFile(filePath) {
  await assertTextPath(filePath);
  const stat = await fs.stat(filePath);
  if (!stat.isFile()) {
    throw new Error("Path is not a file.");
  }
}

async function assertTextPath(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (!textExtensions.has(ext)) {
    throw new Error(`Unsupported file extension: ${ext || "(none)"}`);
  }
}

async function listEntries(rootPath, rootRelative, recursive) {
  const rows = [];
  const names = await fs.readdir(rootPath, { withFileTypes: true });
  for (const entry of names) {
    if (entry.name.startsWith(".")) continue;
    const relativePath = [rootRelative, entry.name].filter(Boolean).join("/");
    const absolutePath = path.join(rootPath, entry.name);
    const stat = await fs.stat(absolutePath);
    rows.push({
      path: relativePath,
      type: entry.isDirectory() ? "directory" : "file",
      size: entry.isDirectory() ? undefined : stat.size,
      modified_at: stat.mtime.toISOString(),
    });
    if (recursive && entry.isDirectory()) {
      rows.push(...(await listEntries(absolutePath, relativePath, true)));
    }
  }
  return rows;
}

async function searchFiles(rootPath, rootRelative, query, maxResults) {
  const needle = query.toLowerCase();
  const entries = await listEntries(rootPath, rootRelative, true);
  const results = [];
  for (const entry of entries) {
    if (entry.type !== "file") continue;
    const target = await resolveWorkspacePath(entry.path);
    if (!textExtensions.has(path.extname(target.absolutePath).toLowerCase())) continue;
    const stat = await fs.stat(target.absolutePath);
    if (stat.size > config.maxFileBytes) continue;
    const content = await fs.readFile(target.absolutePath, "utf8");
    const index = content.toLowerCase().indexOf(needle);
    if (index === -1) continue;
    results.push({
      path: entry.path,
      title: path.basename(entry.path),
      context: snippet(content, index, query.length),
      modified_at: entry.modified_at,
    });
    if (results.length >= maxResults) break;
  }
  return results;
}

async function backupIfExists(filePath, relativePath) {
  try {
    const stat = await fs.stat(filePath);
    if (!stat.isFile()) return;
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  const backupPath = path.join(config.historyRoot, `${timestamp()}__${relativePath.replaceAll("/", "__")}`);
  await ensureParent(backupPath);
  await fs.copyFile(filePath, backupPath);
}

async function moveAcrossDevices(sourcePath, destinationPath) {
  try {
    await fs.rename(sourcePath, destinationPath);
  } catch (error) {
    if (error.code !== "EXDEV") {
      throw error;
    }
    await fs.copyFile(sourcePath, destinationPath);
    await fs.unlink(sourcePath);
  }
}

async function audit(action, payload) {
  const record = {
    time: new Date().toISOString(),
    action,
    ...payload,
  };
  await fs.appendFile(config.auditLog, `${JSON.stringify(record)}\n`, "utf8");
}

async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

async function ensureParent(filePath) {
  await ensureDir(path.dirname(filePath));
}

async function ensureFile(filePath) {
  await ensureParent(filePath);
  const handle = await fs.open(filePath, "a");
  await handle.close();
}

function textResult(value) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(value),
      },
    ],
  };
}

function jsonRpcError(id, code, message) {
  return {
    jsonrpc: "2.0",
    id,
    error: { code, message },
  };
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function constantTimeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function timestamp() {
  return new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
}

function snippet(content, index, length) {
  const start = Math.max(0, index - 120);
  const end = Math.min(content.length, index + length + 120);
  return content.slice(start, end);
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
