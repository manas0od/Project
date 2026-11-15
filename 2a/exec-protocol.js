// CFB terminal tools: pure protocol logic (no Cloudflare imports, so it can be
// unit-tested with plain Node).
//
// SECURITY MODEL (read this first)
//  * These tools are OFF unless the Worker secret/var CFB_EXEC_ENABLED is "1".
//  * Claude can only REQUEST a command. It can never approve one. Approval
//    happens on the phone, inside the Termux agent, from the keyboard.
//  * This module never decides whether a command is safe. The agent does.
//    Everything the agent reports back is treated as untrusted data and is
//    sanitised before it is stored or shown to Claude.

export const EXEC_LIMITS = Object.freeze({
  MAX_COMMAND_CHARS: 2000,
  MAX_CWD_CHARS: 500,
  DEFAULT_TIMEOUT_S: 30,
  MIN_TIMEOUT_S: 1,
  MAX_TIMEOUT_S: 300,
  MAX_WAIT_S: 25,
  MAX_JOBS_KEPT: 100,
  MAX_ACTIVE_JOBS: 5,
  MAX_STREAM_CHARS: 49152,
  MAX_WS_MESSAGE: 262144,
  LOST_AFTER_EXTRA_S: 900
});

export const NONTERMINAL = new Set(["sent", "pending_approval", "approved", "running"]);

export const TERMINAL = new Set([
  "completed",
  "blocked",
  "rejected",
  "expired",
  "cancelled",
  "timed_out",
  "output_limit",
  "error",
  "lost"
]);

const ALL_STATES = new Set([...NONTERMINAL, ...TERMINAL]);
const AGENT_MAY_NOT_REPORT = new Set(["sent", "lost"]); // DO-only states
const ID_RE = /^[a-f0-9]{32}$/;
const KEY = "job:";

export function execEnabled(env) {
  return env?.CFB_EXEC_ENABLED === "1";
}

export function isTerminal(state) {
  return TERMINAL.has(state);
}

// ---------- tool definitions ----------

export const EXEC_TOOLS = [
  {
    name: "terminal_execute",
    description:
      "Request that a command be run in the user's Termux. This does NOT run it. " +
      "The command is queued and the HUMAN must approve that exact command on the phone's Termux screen; " +
      "you cannot approve it and must not claim it ran until terminal_status shows state=completed with an exit_code. " +
      "Commands run without a shell: no pipes, redirects, globs, $VARS or command substitution. " +
      "Only an allowlist of programs works (pwd ls cat head tail wc stat du find grep echo mkdir touch cp mv rm rmdir git node python npm). " +
      "working_directory must be inside the permitted workspace. Show the user the exact command text.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Exact command line, e.g. \"ls -la src\".", maxLength: 2000 },
        working_directory: { type: "string", description: "Directory inside the permitted workspace (default: the workspace).", maxLength: 500 },
        timeout_seconds: { type: "integer", minimum: 1, maximum: 300, description: "Kill the command after this many seconds (default 30)." }
      },
      required: ["command"],
      additionalProperties: false
    }
  },
  {
    name: "terminal_status",
    description:
      "Get the state of a command requested with terminal_execute (pass command_id), or list recent commands (no command_id). " +
      "wait_seconds (max 25) waits for the command to finish. A command succeeded only if succeeded=true (state completed AND exit_code 0).",
    inputSchema: {
      type: "object",
      properties: {
        command_id: { type: "string", pattern: "^[a-f0-9]{32}$" },
        wait_seconds: { type: "integer", minimum: 0, maximum: 25 }
      },
      additionalProperties: false
    }
  },
  {
    name: "terminal_cancel",
    description:
      "Withdraw a pending command or stop a running one. This is not an approval mechanism.",
    inputSchema: {
      type: "object",
      properties: {
        command_id: { type: "string", pattern: "^[a-f0-9]{32}$" }
      },
      required: ["command_id"],
      additionalProperties: false
    }
  }
];

export const EXEC_TOOL_NAMES = new Set(EXEC_TOOLS.map(t => t.name));

export function toolsFor(env) {
  return execEnabled(env) ? EXEC_TOOLS : [];
}

// ---------- argument validation ----------

const isPlainObject = v => v !== null && typeof v === "object" && !Array.isArray(v);
const CONTROL = /[\u0000-\u0008\u000a-\u001f\u007f]/;
const fail = error => ({ ok: false, error });

function onlyKeys(obj, allowed) {
  return Object.keys(obj).every(k => allowed.includes(k));
}

export function validateExecuteArgs(args) {
  if (!isPlainObject(args)) return fail("Arguments must be an object.");
  if (!onlyKeys(args, ["command", "working_directory", "timeout_seconds"])) return fail("Unknown argument.");

  const { command, working_directory, timeout_seconds } = args;

  if (typeof command !== "string" || command.trim() === "" || command.length > EXEC_LIMITS.MAX_COMMAND_CHARS) {
    return fail(`command must be a non-empty string up to ${EXEC_LIMITS.MAX_COMMAND_CHARS} characters.`);
  }
  if (CONTROL.test(command)) return fail("command must not contain control characters or newlines.");

  if (working_directory !== undefined) {
    if (typeof working_directory !== "string" || working_directory === "" || working_directory.length > EXEC_LIMITS.MAX_CWD_CHARS || CONTROL.test(working_directory)) {
      return fail("working_directory must be a plain path string.");
    }
  }

  let timeout = EXEC_LIMITS.DEFAULT_TIMEOUT_S;
  if (timeout_seconds !== undefined) {
    if (!Number.isInteger(timeout_seconds) || timeout_seconds < EXEC_LIMITS.MIN_TIMEOUT_S || timeout_seconds > EXEC_LIMITS.MAX_TIMEOUT_S) {
      return fail(`timeout_seconds must be an integer from ${EXEC_LIMITS.MIN_TIMEOUT_S} to ${EXEC_LIMITS.MAX_TIMEOUT_S}.`);
    }
    timeout = timeout_seconds;
  }

  return { ok: true, value: { command, working_directory, timeout_seconds: timeout } };
}

export function validateStatusArgs(args) {
  if (!isPlainObject(args)) return fail("Arguments must be an object.");
  if (!onlyKeys(args, ["command_id", "wait_seconds"])) return fail("Unknown argument.");
  const { command_id, wait_seconds } = args;
  if (command_id !== undefined && (typeof command_id !== "string" || !ID_RE.test(command_id))) return fail("command_id is not valid.");
  let wait = 0;
  if (wait_seconds !== undefined) {
    if (!Number.isInteger(wait_seconds) || wait_seconds < 0 || wait_seconds > EXEC_LIMITS.MAX_WAIT_S) {
      return fail(`wait_seconds must be an integer from 0 to ${EXEC_LIMITS.MAX_WAIT_S}.`);
    }
    wait = wait_seconds;
  }
  return { ok: true, value: { command_id, wait_seconds: wait } };
}

export function validateCancelArgs(args) {
  if (!isPlainObject(args)) return fail("Arguments must be an object.");
  if (!onlyKeys(args, ["command_id"])) return fail("Unknown argument.");
  if (typeof args.command_id !== "string" || !ID_RE.test(args.command_id)) return fail("command_id is not valid.");
  return { ok: true, value: { command_id: args.command_id } };
}

export function newCommandId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

// ---------- sanitising what the agent sends back ----------

const str = (v, n) => (typeof v === "string" ? v.slice(0, n) : undefined);
const num = v => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const bool = v => (typeof v === "boolean" ? v : undefined);
const strArray = (v, count, len) =>
  Array.isArray(v) ? v.slice(0, count).map(x => String(x).slice(0, len)) : undefined;

export function sanitizeAgentJob(raw) {
  if (!isPlainObject(raw)) return null;
  if (typeof raw.command_id !== "string" || !ID_RE.test(raw.command_id)) return null;
  if (!ALL_STATES.has(raw.state) || AGENT_MAY_NOT_REPORT.has(raw.state)) return null;

  const job = { command_id: raw.command_id, state: raw.state };
  const set = (k, v) => { if (v !== undefined) job[k] = v; };

  if (["low", "medium", "high"].includes(raw.risk)) job.risk = raw.risk;
  set("reasons", strArray(raw.reasons, 10, 300));
  set("effective_argv", strArray(raw.effective_argv, 64, 1000));
  set("cwd", str(raw.cwd, EXEC_LIMITS.MAX_CWD_CHARS));
  set("approved_at", num(raw.approved_at));
  set("started_at", num(raw.started_at));
  set("finished_at", num(raw.finished_at));
  set("timed_out", bool(raw.timed_out));
  set("stdout", str(raw.stdout, EXEC_LIMITS.MAX_STREAM_CHARS));
  set("stderr", str(raw.stderr, EXEC_LIMITS.MAX_STREAM_CHARS));
  set("stdout_truncated", bool(raw.stdout_truncated));
  set("stderr_truncated", bool(raw.stderr_truncated));
  set("error", str(raw.error, 500));
  set("signal", str(raw.signal, 32));
  if (raw.exit_code === null) job.exit_code = null;
  else set("exit_code", Number.isInteger(raw.exit_code) ? raw.exit_code : undefined);
  if (isPlainObject(raw.script)) {
    job.script = {
      path: str(raw.script.path, 500) ?? "",
      bytes: num(raw.script.bytes) ?? 0,
      sha256: str(raw.script.sha256, 64) ?? ""
    };
  }
  return job;
}

// ---------- presentation for Claude ----------

function nextStep(job) {
  switch (job.state) {
    case "sent":
    case "pending_approval":
      return "WAITING FOR HUMAN APPROVAL. The user must approve this exact command on the Termux screen. You cannot approve it. Show the user the command and ask them to approve it, then call terminal_status with this command_id and wait_seconds.";
    case "approved":
    case "running":
      return "Running. Call terminal_status with this command_id and wait_seconds to wait for the result.";
    case "completed":
      return job.exit_code === 0
        ? "Finished with exit code 0."
        : "Finished but FAILED: the exit code was not 0 (or it was killed by a signal). Do not report this as a success.";
    case "blocked":
      return "BLOCKED by the agent's safety policy (see reasons). Do not try to disguise or work around the block; explain it to the user instead.";
    case "rejected":
      return "The user rejected this command. Do not run it again unless the user asks.";
    case "expired":
      return "Nobody approved the command in time, so it did not run.";
    case "cancelled":
      return "Cancelled. The command did not complete.";
    case "timed_out":
      return "Killed because it exceeded its timeout. The command did not complete.";
    case "output_limit":
      return "Killed because its output exceeded the size limit. Output shown is partial.";
    case "lost":
      return "The agent restarted or lost track of this command. Its outcome is UNKNOWN; do not assume it ran or did not run.";
    default:
      return "Error. The command did not complete.";
  }
}

export function presentJob(job) {
  const terminal = isTerminal(job.state);
  const out = {
    command_id: job.command_id,
    state: job.state,
    terminal,
    succeeded: job.state === "completed" && job.exit_code === 0,
    command: job.command,
    working_directory: job.cwd ?? job.cwd_requested ?? null,
    timeout_seconds: job.timeout_seconds
  };
  for (const k of ["risk", "reasons", "effective_argv", "script", "exit_code", "signal", "timed_out", "stdout", "stderr", "stdout_truncated", "stderr_truncated", "error"]) {
    if (job[k] !== undefined) out[k] = job[k];
  }
  out.next_step = nextStep(job);
  return out;
}

const okResult = payload => ({
  content: [{ type: "text", text: JSON.stringify(payload) }],
  structuredContent: payload,
  isError: false
});

const errResult = (code, message) => ({
  content: [{ type: "text", text: JSON.stringify({ error: code, message }) }],
  isError: true
});

// ---------- the job store (runs inside the Durable Object) ----------

export class ExecJobs {
  // storage: { get, put, delete, list({prefix}) }  (Durable Object storage API)
  // sendToAgent(msg) -> boolean, agentConnected() -> boolean
  constructor({ storage, sendToAgent, agentConnected, now = () => Date.now() }) {
    this.storage = storage;
    this.sendToAgent = sendToAgent;
    this.agentConnected = agentConnected;
    this.now = now;
    this.waiters = new Map();
  }

  async get(id) {
    if (typeof id !== "string" || !ID_RE.test(id)) return null;
    const job = await this.storage.get(KEY + id);
    if (!job) return null;
    // If the agent has been silent for far longer than the command could have
    // lived, stop reporting it as active. Outcome is unknown, never "success".
    const horizon = (job.timeout_seconds ?? EXEC_LIMITS.DEFAULT_TIMEOUT_S) + EXEC_LIMITS.LOST_AFTER_EXTRA_S;
    if (NONTERMINAL.has(job.state) && this.now() - job.created_at > horizon * 1000) {
      job.state = "lost";
      job.error = "No update from the agent for a long time; outcome unknown.";
      await this.storage.put(KEY + id, job);
    }
    return job;
  }

  async list() {
    const map = await this.storage.list({ prefix: KEY });
    return [...map.values()].sort((a, b) => b.created_at - a.created_at);
  }

  async create(args) {
    const v = validateExecuteArgs(args);
    if (!v.ok) return { ok: false, code: "invalid_arguments", error: v.error };

    if (!this.agentConnected()) {
      return { ok: false, code: "agent_unavailable", error: "The Termux agent is not connected, so nothing was queued." };
    }

    const active = (await this.list()).filter(j => NONTERMINAL.has(j.state)).length;
    if (active >= EXEC_LIMITS.MAX_ACTIVE_JOBS) {
      return { ok: false, code: "too_many_active", error: "Too many commands are already waiting or running." };
    }

    const id = newCommandId();
    const job = {
      command_id: id,
      state: "sent",
      command: v.value.command,
      cwd_requested: v.value.working_directory ?? null,
      timeout_seconds: v.value.timeout_seconds,
      created_at: this.now()
    };
    await this.storage.put(KEY + id, job);

    const delivered = this.sendToAgent({
      type: "exec_request",
      command_id: id,
      command: job.command,
      working_directory: v.value.working_directory,
      timeout_seconds: job.timeout_seconds
    });

    if (!delivered) {
      job.state = "error";
      job.error = "Could not deliver the request to the agent.";
      await this.storage.put(KEY + id, job);
      return { ok: false, code: "agent_unavailable", error: job.error };
    }

    await this.prune();
    // Give the agent a moment to classify it so Claude sees an instant block or the risk level.
    const first = await this.waitFor(id, 3000, j => j.state !== "sent");
    return { ok: true, job: first ?? (await this.get(id)) };
  }

  async status(args) {
    const v = validateStatusArgs(args);
    if (!v.ok) return { ok: false, code: "invalid_arguments", error: v.error };

    if (!v.value.command_id) {
      const jobs = (await this.list()).slice(0, 20);
      const out = [];
      for (const j of jobs) out.push((await this.get(j.command_id)) ?? j);
      return { ok: true, list: out };
    }

    let job = await this.get(v.value.command_id);
    if (!job) return { ok: false, code: "not_found", error: "Unknown command_id." };

    if (v.value.wait_seconds > 0 && !isTerminal(job.state)) {
      job = (await this.waitFor(job.command_id, v.value.wait_seconds * 1000, j => isTerminal(j.state))) ?? (await this.get(job.command_id));
    }
    return { ok: true, job };
  }

  async cancel(args) {
    const v = validateCancelArgs(args);
    if (!v.ok) return { ok: false, code: "invalid_arguments", error: v.error };

    const job = await this.get(v.value.command_id);
    if (!job) return { ok: false, code: "not_found", error: "Unknown command_id." };
    if (isTerminal(job.state)) return { ok: true, job };

    if (!this.agentConnected() || !this.sendToAgent({ type: "exec_cancel", command_id: job.command_id })) {
      return { ok: false, code: "agent_unavailable", error: "The agent is not connected; the cancel could not be delivered." };
    }
    const after = await this.waitFor(job.command_id, 3000, j => isTerminal(j.state));
    return { ok: true, job: after ?? (await this.get(job.command_id)) };
  }

  // Agent -> store. The agent is the authority for a job's lifecycle, but it can
  // never create jobs, never resurrect a finished one and never set DO-only states.
  async onAgentUpdate(raw) {
    const clean = sanitizeAgentJob(raw);
    if (!clean) return false;
    const existing = await this.storage.get(KEY + clean.command_id);
    if (!existing || isTerminal(existing.state)) return false;
    const merged = { ...existing, ...clean, created_at: existing.created_at };
    await this.storage.put(KEY + merged.command_id, merged);
    this.notify(merged);
    return true;
  }

  // On every (re)connect the agent reports what it remembers. Anything the store
  // thinks is active but the agent does not know about (and that predates this
  // connection) died with an agent restart: mark it lost, never "succeeded".
  async onAgentSync(rawJobs, { connectedAt = 0 } = {}) {
    if (!Array.isArray(rawJobs)) return;
    const known = new Set();
    for (const raw of rawJobs.slice(0, 100)) {
      const clean = sanitizeAgentJob(raw);
      if (!clean) continue;
      known.add(clean.command_id);
      await this.onAgentUpdate(raw);
    }
    for (const job of await this.list()) {
      if (NONTERMINAL.has(job.state) && !known.has(job.command_id) && job.created_at < connectedAt) {
        job.state = "lost";
        job.error = "The agent restarted or forgot this command; outcome unknown.";
        await this.storage.put(KEY + job.command_id, job);
        this.notify(job);
      }
    }
  }

  async prune() {
    const jobs = await this.list();
    if (jobs.length <= EXEC_LIMITS.MAX_JOBS_KEPT) return;
    const doomed = jobs.filter(j => isTerminal(j.state)).slice(EXEC_LIMITS.MAX_JOBS_KEPT - jobs.filter(j => !isTerminal(j.state)).length);
    for (const j of doomed) await this.storage.delete(KEY + j.command_id);
  }

  async waitFor(id, ms, predicate) {
    const current = await this.get(id);
    if (current && predicate(current)) return current;
    return new Promise(resolve => {
      const entry = { predicate, resolve: null };
      const timer = setTimeout(() => { this.removeWaiter(id, entry); resolve(null); }, ms);
      entry.resolve = job => { clearTimeout(timer); this.removeWaiter(id, entry); resolve(job); };
      const list = this.waiters.get(id) ?? [];
      list.push(entry);
      this.waiters.set(id, list);
    });
  }

  removeWaiter(id, entry) {
    const list = (this.waiters.get(id) ?? []).filter(e => e !== entry);
    if (list.length) this.waiters.set(id, list);
    else this.waiters.delete(id);
  }

  notify(job) {
    for (const entry of [...(this.waiters.get(job.command_id) ?? [])]) {
      if (entry.predicate(job)) entry.resolve(job);
    }
  }
}

// ---------- tool dispatcher (called by the Durable Object) ----------

export async function handleTerminalTool(name, args, jobs) {
  if (name === "terminal_execute") {
    const r = await jobs.create(args);
    return r.ok ? okResult(presentJob(r.job)) : errResult(r.code, r.error);
  }
  if (name === "terminal_status") {
    const r = await jobs.status(args);
    if (!r.ok) return errResult(r.code, r.error);
    if (r.list) {
      return okResult({
        agent_connected: jobs.agentConnected(),
        commands: r.list.map(j => ({
          command_id: j.command_id,
          state: j.state,
          succeeded: j.state === "completed" && j.exit_code === 0,
          command: j.command.slice(0, 120),
          exit_code: j.exit_code ?? null
        }))
      });
    }
    return okResult({ agent_connected: jobs.agentConnected(), ...presentJob(r.job) });
  }
  if (name === "terminal_cancel") {
    const r = await jobs.cancel(args);
    return r.ok ? okResult(presentJob(r.job)) : errResult(r.code, r.error);
  }
  return errResult("unknown_tool", "Unknown tool.");
}
