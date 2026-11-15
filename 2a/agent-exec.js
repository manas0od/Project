"use strict";

// CFB agent: controlled command execution.
//
// WHAT THIS IS NOT: a sandbox. Android/Termux without root offers no real
// isolation, so an approved `node` or `python` script can do anything your
// Termux user can. The real security boundary is YOU reading each command
// before approving it. The code below is defence in depth around that:
//
//   1. Off by default (needs ~/.cfb/config.json with exec.enabled = true).
//   2. No shell. The command string is parsed into argv and spawned directly,
//      so pipes, redirects, globs, $VARS and `backticks` cannot do anything.
//   3. Allowlist of programs, with per-program option and path rules.
//   4. Every path is resolved (symlinks followed) and must stay inside ~/cfb.
//   5. Every command needs a human "yes <code>" typed on this device.
//   6. Approval is bound to a fingerprint of the exact argv, directory,
//      timeout and script hash, and is re-verified right before spawning.
//   7. Child processes get a scrubbed environment and a separate HOME.

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");

const ID_RE = /^[a-f0-9]{32}$/;
const MAX_TOKENS = 64;
const MAX_TOKEN_LEN = 1000;
const MAX_SCRIPT_BYTES = 1024 * 1024;
const MAX_KEPT_JOBS = 50;

const show = s => JSON.stringify(String(s).slice(0, 120));

// ---------------------------------------------------------------- config

function expandHome(p, home) {
  if (p === "~") return home;
  if (typeof p === "string" && p.startsWith("~/")) return path.join(home, p.slice(2));
  return p;
}

function within(root, p) {
  return p === root || p.startsWith(root + path.sep);
}

function realpathLoose(p, depth = 0) {
  // Resolve symlinks in the longest existing prefix; follow dangling symlinks
  // too, so a link pointing outside to a not-yet-existing file cannot be used
  // as a write target.
  if (depth > 40) throw new Error("too many symlink levels");
  let cur = path.resolve(p);
  const rest = [];
  for (;;) {
    try {
      const real = fs.realpathSync.native(cur);
      return rest.length ? path.join(real, ...rest.reverse()) : real;
    } catch (e) {
      if (e.code !== "ENOENT" && e.code !== "ENOTDIR") throw e;
      try {
        if (fs.lstatSync(cur).isSymbolicLink()) {
          const target = path.resolve(path.dirname(cur), fs.readlinkSync(cur));
          const resolved = realpathLoose(target, depth + 1);
          return rest.length ? path.join(resolved, ...rest.reverse()) : resolved;
        }
      } catch {}
      const parent = path.dirname(cur);
      if (parent === cur) return path.resolve(p);
      rest.push(path.basename(cur));
      cur = parent;
    }
  }
}

function loadConfig({ home = os.homedir(), file, base } = {}) {
  const baseDir = base || path.join(home, "cfb");
  const cfgFile = file || path.join(home, ".cfb", "config.json");
  const off = reason => ({ enabled: false, reason });

  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(cfgFile, "utf8"));
  } catch (e) {
    return off(e.code === "ENOENT" ? `no config file at ${cfgFile}` : `config file unreadable: ${e.message}`);
  }
  const ex = raw && raw.exec;
  if (!ex || ex.enabled !== true) return off("exec.enabled is not true in the config file");

  let baseReal;
  try {
    baseReal = fs.realpathSync.native(baseDir);
  } catch {
    return off(`workspace ${baseDir} does not exist`);
  }

  const roots = [];
  for (const r of ex.roots || [baseDir]) {
    let real;
    try {
      real = fs.realpathSync.native(expandHome(r, home));
    } catch {
      return off(`configured root ${show(r)} does not exist`);
    }
    // Hard rule for v1: roots may only be the workspace itself or inside it.
    if (!within(baseReal, real)) return off(`configured root ${show(r)} is outside ${baseDir}`);
    roots.push(real);
  }
  if (!roots.length) return off("no roots configured");

  let defaultCwd;
  try {
    defaultCwd = fs.realpathSync.native(expandHome(ex.default_cwd || roots[0], home));
  } catch {
    return off("default_cwd does not exist");
  }
  if (!roots.some(r => within(r, defaultCwd))) return off("default_cwd is outside the configured roots");

  const clamp = (v, lo, hi, d) => (Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.floor(v))) : d);

  return {
    enabled: true,
    baseReal,
    roots,
    defaultCwd,
    maxTimeoutSeconds: clamp(ex.max_timeout_seconds, 1, 600, 300),
    approvalTtlSeconds: clamp(ex.approval_ttl_seconds, 15, 600, 120),
    outputLimitBytes: clamp(ex.output_limit_bytes, 1024, 49152, 20000),
    maxPending: clamp(ex.max_pending, 1, 20, 5),
    useTimeoutWrapper: ex.use_timeout_wrapper !== false
  };
}

// ---------------------------------------------------------------- tokenizer

const SHELL_META = new Set(["|", "&", ";", "<", ">", "(", ")", "{", "}", "$", "`", "!", "*", "?", "[", "]", "~"]);

// Splits a command line into argv WITHOUT a shell. Anything that would mean
// something to a shell is refused instead of being passed through quietly.
function tokenize(cmd) {
  if (typeof cmd !== "string" || cmd.trim() === "") return { ok: false, reason: "empty command" };
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(cmd)) return { ok: false, reason: "control characters and newlines are not allowed" };

  const argv = [];
  let cur = "";
  let started = false;
  let quote = null;

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (quote === "'") {
      if (ch === "'") quote = null;
      else cur += ch;
    } else if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === "\\" && (cmd[i + 1] === '"' || cmd[i + 1] === "\\")) cur += cmd[++i];
      else cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      started = true;
    } else if (ch === " " || ch === "\t") {
      if (started) { argv.push(cur); cur = ""; started = false; }
    } else if (ch === "\\") {
      if (i + 1 >= cmd.length) return { ok: false, reason: "dangling backslash" };
      cur += cmd[++i];
      started = true;
    } else if (SHELL_META.has(ch)) {
      return { ok: false, reason: `unsupported shell syntax ${show(ch)} (commands run without a shell: no pipes, redirects, globs, variables or substitution)` };
    } else if (ch === "#" && !started) {
      return { ok: false, reason: "comments are not supported" };
    } else {
      cur += ch;
      started = true;
    }
  }
  if (quote) return { ok: false, reason: "unterminated quote" };
  if (started) argv.push(cur);
  if (!argv.length) return { ok: false, reason: "empty command" };
  if (argv.length > MAX_TOKENS) return { ok: false, reason: "too many arguments" };
  if (argv.some(a => a.length > MAX_TOKEN_LEN)) return { ok: false, reason: "argument too long" };
  return { ok: true, argv };
}

// ---------------------------------------------------------------- path guard

// Names that must never be readable or writable through the file tools.
const PROTECTED_SEGMENT =
  /^(\.env(\..*)?|\.npmrc|\.netrc|\.git-credentials|\.pgpass|\.git|\.ssh|\.gnupg|\.aws|\.cfb|\.cfb-home|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|bridge\.token|credentials(\.json)?|.*\.(pem|key|p12|pfx|jks|keystore))$/i;

function checkPath(arg, cwd, roots, { allowRoot = true } = {}) {
  if (typeof arg !== "string" || arg.includes("\0")) return { ok: false, reason: "invalid path" };
  let real;
  try {
    real = realpathLoose(path.resolve(cwd, arg));
  } catch (e) {
    return { ok: false, reason: `cannot resolve path ${show(arg)}` };
  }
  const root = roots.find(r => within(r, real));
  if (!root) return { ok: false, reason: `path ${show(arg)} is outside the permitted directories` };
  if (real === root && !allowRoot) return { ok: false, reason: `operating on the workspace root itself is not allowed (${show(arg)})` };
  for (const seg of path.relative(root, real).split(path.sep)) {
    if (seg && PROTECTED_SEGMENT.test(seg)) return { ok: false, reason: `path ${show(arg)} refers to a protected file or directory name (${show(seg)})` };
  }
  return { ok: true, real };
}

// ---------------------------------------------------------------- policy

const blocked = (...reasons) => ({ ok: false, reasons });
const allow = (risk, reasons, argv, extra = {}) => ({ ok: true, risk, reasons, argv, ...extra });

// Explains WHY common dangerous programs are refused (everything off the
// allowlist is refused anyway; this just gives Claude and you a clear reason).
const DANGEROUS_NAMES = new Map([
  [/^(sudo|su|tsu|doas|pkexec|root)$/, "attempts to gain root access"],
  [/^(dd|mkfs(\..*)?|fdisk|parted|mount|umount|losetup|wipefs|shred|truncate)$/, "formatting, partition or raw-disk operation"],
  [/^(pm|am|cmd|settings|svc|wm|appops|dumpsys|getprop|setprop|content|input|screencap|logcat|su)$/, "Android system or settings access"],
  [/^(curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|ftp|telnet|rsync|aria2c|npx|pip|pip3|pkg|apt|apt-get|dpkg)$/, "network download/exfiltration or package installation outside policy"],
  [/^(bash|sh|zsh|dash|ash|fish|ksh|eval|exec|source|xargs|nohup|setsid|timeout|env|time|watch|script|screen|tmux)$/, "shell or indirection (would bypass argument checks)"],
  [/^(printenv|set|export|declare)$/, "reads environment variables, which can hold secrets"],
  [/^termux-.*$/, "Termux:API device access (camera, location, SMS, clipboard...)"],
  [/^(chmod|chown|chgrp|ln|install|tar|unzip|zip|gzip|gunzip|7z|patch|sed|awk|perl|ruby|php|lua|tee|dd)$/, "not on the allowlist (can overwrite or reinterpret files)"]
]);

const LETTERS = {
  ls: "alhRdtF1rSsi",
  cat: "nbs",
  head: "nqv0123456789c",
  tail: "nqv0123456789c",
  wc: "lwcm",
  stat: "",
  du: "shakc",
  mkdir: "pv",
  touch: "",
  rm: "v",
  rmdir: "v",
  cp: "rnvpa",
  mv: "nv"
};

function splitOptions(args, letters) {
  const flags = [];
  const operands = [];
  let endOfOptions = false;
  for (const a of args) {
    if (!endOfOptions && a === "--") { endOfOptions = true; continue; }
    if (!endOfOptions && a.startsWith("-") && a.length > 1) {
      if (!/^-[A-Za-z0-9]+$/.test(a)) return { err: `option ${show(a)} is not allowed` };
      for (const ch of a.slice(1)) {
        if (!letters.includes(ch)) return { err: `option -${ch} is not allowed for this command` };
      }
      flags.push(a);
    } else {
      operands.push(a);
    }
  }
  return { flags, operands };
}

function fileTool(name, { risk, min = 0, max = Infinity, mutate = false, destMayBeRoot = false }) {
  return (args, ctx) => {
    const s = splitOptions(args, LETTERS[name]);
    if (s.err) return blocked(s.err);
    if (s.operands.length < min) return blocked(`${name} needs at least ${min} path argument(s)`);
    if (s.operands.length > max) return blocked(`${name} accepts at most ${max} path argument(s)`);
    for (let i = 0; i < s.operands.length; i++) {
      const isDest = destMayBeRoot && i === s.operands.length - 1;
      const c = checkPath(s.operands[i], ctx.cwd, ctx.roots, { allowRoot: !mutate || isDest });
      if (!c.ok) return blocked(c.reason);
    }
    return allow(risk, mutate ? ["modifies files inside the workspace"] : [], [name, ...args]);
  };
}

const FIND_EXPR = { "-name": 1, "-iname": 1, "-path": 1, "-ipath": 1, "-type": 1, "-maxdepth": 1, "-mindepth": 1, "-size": 1, "-mtime": 1, "-mmin": 1, "-empty": 0, "-print": 0, "-not": 0 };
const GREP_HARDENING = [
  "--exclude=.env*", "--exclude=.npmrc", "--exclude=.netrc", "--exclude=.git-credentials",
  "--exclude=*.pem", "--exclude=*.key", "--exclude=bridge.token",
  "--exclude-dir=.git", "--exclude-dir=.ssh", "--exclude-dir=.cfb", "--exclude-dir=.cfb-home"
];

function findTool(args, ctx) {
  let i = 0;
  while (i < args.length && !args[i].startsWith("-")) {
    const c = checkPath(args[i], ctx.cwd, ctx.roots);
    if (!c.ok) return blocked(c.reason);
    i++;
  }
  for (; i < args.length;) {
    const tok = args[i++];
    if (!Object.prototype.hasOwnProperty.call(FIND_EXPR, tok)) {
      return blocked(`find expression ${show(tok)} is not allowed (no -exec, -delete or -fprint)`);
    }
    if (FIND_EXPR[tok] === 1 && args[i++] === undefined) return blocked(`find ${tok} needs a value`);
  }
  return allow("low", [], ["find", ...args]);
}

function grepTool(args, ctx) {
  const s = splitOptions(args, "rnilvcEFwHsoqI");
  if (s.err) return blocked(s.err);
  if (!s.operands.length) return blocked("grep needs a pattern");
  for (const p of s.operands.slice(1)) {
    const c = checkPath(p, ctx.cwd, ctx.roots);
    if (!c.ok) return blocked(c.reason);
  }
  return allow("low", ["recursive searches skip files with protected names"], ["grep", ...GREP_HARDENING, ...args]);
}

function scriptTool(name, exts) {
  return (args, ctx) => {
    if (!args.length) return blocked(`${name} needs a script file (interactive mode is not allowed)`);
    const [file, ...rest] = args;
    if (file.startsWith("-")) {
      if (args.length === 1 && ["--version", "-v", "-V"].includes(file)) return allow("low", [], [name, file]);
      return blocked(`option ${show(file)} is not allowed: inline code (-e/-c/-p/--eval), -m and similar are blocked; run a script file instead`);
    }
    const c = checkPath(file, ctx.cwd, ctx.roots, { allowRoot: false });
    if (!c.ok) return blocked(c.reason);
    if (!exts.includes(path.extname(c.real).toLowerCase())) return blocked(`${name} only runs ${exts.join(" / ")} files`);
    let st;
    let data;
    try {
      st = fs.statSync(c.real);
      if (!st.isFile()) return blocked("script is not a regular file");
      if (st.size > MAX_SCRIPT_BYTES) return blocked("script is larger than 1 MB");
      data = fs.readFileSync(c.real);
    } catch {
      return blocked("script file cannot be read");
    }
    return allow(
      "high",
      ["runs arbitrary code from a script file; the script's behaviour is NOT analysed, only its hash is pinned"],
      [name, c.real, ...rest],
      { script: { path: c.real, bytes: data.length, sha256: crypto.createHash("sha256").update(data).digest("hex") } }
    );
  };
}

const GIT_RISK = {
  status: "low", log: "low", diff: "low", show: "low", "rev-parse": "low", "ls-files": "low", blame: "low", describe: "low",
  add: "medium", commit: "medium", init: "medium", checkout: "medium", switch: "medium", restore: "medium",
  stash: "medium", tag: "medium", branch: "medium", merge: "medium", mv: "medium", rm: "medium", reset: "medium"
};
const GIT_BAD_FLAG = /^(-c|-C|--exec-path.*|--git-dir.*|--work-tree.*|--upload-pack.*|--receive-pack.*|--config.*|--output(=.*)?|-o|--ext-diff|--textconv|--hard|--force|-f|--no-verify|--template.*|--exec.*|--super-prefix.*)$/;

function gitTool(args, ctx) {
  const sub = args[0];
  if (!sub || sub.startsWith("-")) return blocked("git options before the subcommand (-c, -C, --git-dir...) are not allowed");
  if (!Object.prototype.hasOwnProperty.call(GIT_RISK, sub)) {
    return blocked(`git ${show(sub)} is not allowed (config, clone, fetch, pull, push, remote and credential commands are blocked in this version)`);
  }
  const rest = args.slice(1);
  for (const a of rest) {
    if (a === "--") break;
    if (a.startsWith("-")) {
      if (!/^--?[A-Za-z][A-Za-z0-9-]*(=[^\s]*)?$/.test(a) || GIT_BAD_FLAG.test(a)) return blocked(`git option ${show(a)} is not allowed`);
    }
  }
  // Paths after "--" (and plain operands for add/rm/mv/restore) must stay in the workspace.
  const dd = rest.indexOf("--");
  const pathOperands = dd >= 0 ? rest.slice(dd + 1) : ["add", "rm", "mv", "restore"].includes(sub) ? rest.filter(a => !a.startsWith("-")) : [];
  for (const p of pathOperands) {
    const c = checkPath(p, ctx.cwd, ctx.roots);
    if (!c.ok) return blocked(c.reason);
  }
  const risk = GIT_RISK[sub];
  return allow(
    risk,
    risk === "low" ? [] : ["modifies the repository"],
    ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", ...args]
  );
}

const NPM_RISK = { ls: "low", list: "low", outdated: "low", view: "low", init: "medium", install: "high", i: "high", ci: "high", uninstall: "high", run: "high", "run-script": "high", test: "high", t: "high", start: "high" };
const NPM_BAD_FLAG = /^--?(ignore-scripts|registry|userconfig|globalconfig|prefix|global|g|script-shell|cache|location|workspaces?|w|include-workspace-root|foreground-scripts|onload-script|node-options)(=.*)?$/i;

function npmTool(args) {
  const sub = args[0];
  if (!sub || sub.startsWith("-")) return blocked("npm needs a subcommand");
  if (!Object.prototype.hasOwnProperty.call(NPM_RISK, sub)) return blocked(`npm ${show(sub)} is not allowed (config, exec, publish, login, token and similar are blocked)`);
  const dd = args.indexOf("--");
  for (const a of dd >= 0 ? args.slice(1, dd) : args.slice(1)) {
    if (a.startsWith("-") && (!/^--?[a-z][a-z0-9-]*(=\S*)?$/i.test(a) || NPM_BAD_FLAG.test(a))) return blocked(`npm option ${show(a)} is not allowed`);
  }
  const risk = NPM_RISK[sub];
  return allow(
    risk,
    risk === "high" ? ["downloads packages and/or runs project scripts (lifecycle scripts of dependencies are disabled)"] : [],
    ["npm", ...args]
  );
}

const SIMPLE = {
  pwd: (args) => (args.length === 0 || (args.length === 1 && /^-[LP]$/.test(args[0])) ? allow("low", [], ["pwd", ...args]) : blocked("pwd takes no arguments")),
  echo: (args) => allow("low", [], ["echo", ...args]),
  date: (args) => (args.length === 0 || (args.length === 1 && args[0].startsWith("+")) ? allow("low", [], ["date", ...args]) : blocked("date only supports a +FORMAT argument")),
  uname: (args) => (args.every(a => /^-[amrsn]$/.test(a)) ? allow("low", [], ["uname", ...args]) : blocked("uname only supports -a -m -r -s -n")),
  whoami: (args) => (args.length === 0 ? allow("low", [], ["whoami"]) : blocked("whoami takes no arguments")),
  sleep: (args) => (args.length === 1 && /^\d{1,3}$/.test(args[0]) ? allow("low", [], ["sleep", args[0]]) : blocked("sleep takes one whole number of seconds")),
  ls: fileTool("ls", { risk: "low" }),
  cat: fileTool("cat", { risk: "low", min: 1 }),
  head: fileTool("head", { risk: "low", min: 1 }),
  tail: fileTool("tail", { risk: "low", min: 1 }),
  wc: fileTool("wc", { risk: "low", min: 1 }),
  stat: fileTool("stat", { risk: "low", min: 1 }),
  du: fileTool("du", { risk: "low" }),
  find: findTool,
  grep: grepTool,
  mkdir: fileTool("mkdir", { risk: "medium", min: 1, mutate: true }),
  touch: fileTool("touch", { risk: "medium", min: 1, mutate: true }),
  rm: fileTool("rm", { risk: "high", min: 1, mutate: true }),
  rmdir: fileTool("rmdir", { risk: "medium", min: 1, mutate: true }),
  cp: fileTool("cp", { risk: "medium", min: 2, mutate: true, destMayBeRoot: true }),
  mv: fileTool("mv", { risk: "medium", min: 2, mutate: true, destMayBeRoot: true }),
  git: gitTool,
  node: scriptTool("node", [".js", ".mjs", ".cjs"]),
  python: scriptTool("python", [".py"]),
  python3: scriptTool("python3", [".py"]),
  npm: npmTool
};

function classify(argv, ctx) {
  const name = argv[0];
  if (!/^[a-z0-9._+-]+$/i.test(name)) return blocked("the program must be a bare name from the allowlist (paths such as ./x or /bin/x are not allowed)");
  if (!Object.prototype.hasOwnProperty.call(SIMPLE, name)) {
    const reasons = [`${show(name)} is not on the allowlist`];
    for (const [re, why] of DANGEROUS_NAMES) if (re.test(name)) reasons.push(`blocked category: ${why}`);
    return blocked(...reasons);
  }
  return SIMPLE[name](argv.slice(1), ctx);
}

// ---------------------------------------------------------------- redaction

function redactSecrets(text, secrets) {
  let out = String(text ?? "");
  for (const s of secrets) if (typeof s === "string" && s.length >= 8) out = out.split(s).join("[REDACTED]");
  return out;
}

// ---------------------------------------------------------------- approver (a human, on this device)

function sanitizeForTerminal(text) {
  return String(text).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "·");
}

function createTtyApprover({ input = process.stdin, output = process.stderr } = {}) {
  if (!input.isTTY) return null;
  // eslint-disable-next-line global-require
  const readline = require("readline/promises");
  const rl = readline.createInterface({ input, output, terminal: true });
  rl.on("SIGINT", () => process.kill(process.pid, "SIGINT"));
  let chain = Promise.resolve();
  const say = text => output.write(text + "\n");

  async function askNow(info, signal) {
    say("");
    say("==================== CFB: command approval ====================");
    say(`id        : ${info.id}   (code ${info.code})`);
    say(`risk      : ${info.risk.toUpperCase()}${info.reasons.length ? "  - " + info.reasons.map(sanitizeForTerminal).join("; ") : ""}`);
    say(`directory : ${JSON.stringify(info.cwd)}`);
    say(`command   : ${JSON.stringify(info.command)}`);
    say(`will run  : ${JSON.stringify(info.argv)}`);
    say(`timeout   : ${info.timeout_s}s    approval expires in ${info.expires_in_s}s`);
    if (info.script) say(`script    : ${info.script.path}  ${info.script.bytes} bytes  sha256 ${info.script.sha256.slice(0, 16)}...`);
    say("Only approve if you understand EXACTLY what this does.");
    for (;;) {
      let line;
      try {
        line = (await rl.question(`Type "yes ${info.code}" to approve, "no" to reject${info.script ? ', "view" to preview the script' : ""}: `, { signal })).trim().toLowerCase();
      } catch {
        return "timeout";
      }
      if (line === `yes ${info.code}`) return "approve";
      if (line === "no" || line === "n") return "reject";
      if (line === "view" && info.script) {
        try {
          const text = sanitizeForTerminal(fs.readFileSync(info.script.path, "utf8").slice(0, 4000));
          say("--------- first 60 lines (sanitised) ---------");
          say(text.split("\n").slice(0, 60).join("\n"));
          say("----------------------------------------------");
        } catch {
          say("(cannot read the script)");
        }
        continue;
      }
      say("Not understood.");
    }
  }

  return {
    ask(info, { signal } = {}) {
      const run = () => (signal && signal.aborted ? "timeout" : askNow(info, signal));
      const p = chain.then(run, run);
      chain = p.catch(() => {});
      return p;
    },
    close() { try { rl.close(); } catch {} }
  };
}

// ---------------------------------------------------------------- manager

function findTimeoutBin() {
  const candidates = [path.join(process.env.PREFIX || "/usr", "bin", "timeout"), "/usr/bin/timeout", "/bin/timeout"];
  return candidates.find(p => { try { return fs.statSync(p).isFile(); } catch { return false; } }) || null;
}

const ENV_PASSTHROUGH = ["PATH", "PREFIX", "LD_PRELOAD", "LD_LIBRARY_PATH", "ANDROID_ROOT", "ANDROID_DATA", "TMPDIR", "LANG", "LC_ALL", "TZ", "TERMUX_VERSION"];

function createExecManager({ config, approver, send, log = () => {}, secrets = [], now = Date.now, spawnImpl = spawn }) {
  const jobs = new Map();
  const seen = new Set();
  const queue = [];
  let running = null;
  const timeoutBin = config.enabled && config.useTimeoutWrapper ? findTimeoutBin() : null;
  const redact = s => redactSecrets(s, secrets);

  const remember = id => {
    seen.add(id);
    if (seen.size > 2000) seen.delete(seen.values().next().value);
  };

  function snapshot(job) {
    const s = {
      command_id: job.id,
      state: job.state,
      risk: job.risk,
      reasons: job.reasons,
      effective_argv: job.argv ? job.argv.map(redact) : undefined,
      cwd: job.cwd,
      approved_at: job.approved_at,
      started_at: job.started_at,
      finished_at: job.finished_at,
      exit_code: job.exit_code,
      signal: job.signal ?? undefined,
      timed_out: job.timed_out || undefined,
      stdout: job.stdout,
      stderr: job.stderr,
      stdout_truncated: job.stdout_truncated || undefined,
      stderr_truncated: job.stderr_truncated || undefined,
      error: job.error,
      script: job.script
    };
    return s;
  }

  const emit = job => { try { send({ type: "exec_update", job: snapshot(job) }); } catch {} };

  function finish(job, state, extra = {}) {
    if (job.final) return;
    Object.assign(job, extra);
    job.state = state;
    job.final = true;
    job.finished_at = now();
    clearTimeout(job.expiryTimer);
    clearTimeout(job.runTimer);
    clearTimeout(job.killTimer);
    if (job.abort && !job.abort.signal.aborted) job.abort.abort();
    log(`command ${job.id.slice(0, 8)} -> ${state}`);
    emit(job);
    prune();
  }

  function prune() {
    if (jobs.size <= MAX_KEPT_JOBS) return;
    for (const [id, j] of jobs) {
      if (jobs.size <= MAX_KEPT_JOBS) break;
      if (j.final) jobs.delete(id);
    }
  }

  function revalidate(job) {
    const t = tokenize(job.command);
    if (!t.ok) return blocked(t.reason);
    let cwdReal;
    const c = checkPath(job.cwdRequested ?? ".", config.defaultCwd, config.roots);
    if (!c.ok) return blocked(c.reason);
    cwdReal = c.real;
    const cl = classify(t.argv, { cwd: cwdReal, roots: config.roots });
    if (!cl.ok) return cl;
    const fp = fingerprint(cl.argv, cwdReal, job.timeout_s, cl.script);
    if (fp !== job.fingerprint) return blocked("the command, its paths or its script changed after approval was requested; approval is void");
    return { ok: true, cwd: cwdReal, cl };
  }

  function fingerprint(argv, cwd, timeout, script) {
    return crypto.createHash("sha256").update(JSON.stringify({ argv, cwd, timeout, script: script ? script.sha256 : null })).digest("hex");
  }

  function handleRequest(msg) {
    const id = msg && msg.command_id;
    if (typeof id !== "string" || !ID_RE.test(id)) return;

    // Duplicate IDs never run twice and can never change what a given ID means.
    const existing = jobs.get(id);
    if (existing) { emit(existing); return; }
    if (seen.has(id)) {
      send({ type: "exec_update", job: { command_id: id, state: "blocked", reasons: ["duplicate command id"] } });
      return;
    }
    remember(id);

    const job = {
      id,
      code: id.slice(0, 4),
      state: "pending_approval",
      command: typeof msg.command === "string" ? msg.command : "",
      cwdRequested: typeof msg.working_directory === "string" ? msg.working_directory : undefined,
      timeout_s: msg.timeout_seconds,
      created_at: now(),
      risk: "high",
      reasons: [],
      final: false
    };
    jobs.set(id, job);

    const refuse = (...reasons) => finish(job, "blocked", { reasons });

    if (!config.enabled) return refuse(`command execution is disabled on this agent (${config.reason || "not configured"})`);
    if (typeof msg.command !== "string" || job.command.length > 2000) return refuse("invalid command");
    if (!Number.isInteger(job.timeout_s) || job.timeout_s < 1 || job.timeout_s > config.maxTimeoutSeconds) {
      return refuse(`timeout_seconds must be an integer from 1 to ${config.maxTimeoutSeconds}`);
    }
    if ([...jobs.values()].filter(j => j.state === "pending_approval" && j !== job).length >= config.maxPending) {
      return refuse("too many commands are already waiting for approval");
    }

    const t = tokenize(job.command);
    if (!t.ok) return refuse(t.reason);

    const cwd = checkPath(job.cwdRequested ?? ".", config.defaultCwd, config.roots);
    if (!cwd.ok) return refuse(cwd.reason);
    try {
      if (!fs.statSync(cwd.real).isDirectory()) return refuse("working_directory is not a directory");
    } catch {
      return refuse("working_directory does not exist");
    }

    const cl = classify(t.argv, { cwd: cwd.real, roots: config.roots });
    if (!cl.ok) return refuse(...cl.reasons);

    job.argv = cl.argv;
    job.cwd = cwd.real;
    job.risk = cl.risk;
    job.reasons = cl.reasons;
    job.script = cl.script;
    job.fingerprint = fingerprint(cl.argv, cwd.real, job.timeout_s, cl.script);
    job.approvalDeadline = now() + config.approvalTtlSeconds * 1000;
    job.abort = new AbortController();
    job.expiryTimer = setTimeout(() => {
      if (job.state === "pending_approval") finish(job, "expired", { error: "approval window elapsed; nothing was run" });
    }, config.approvalTtlSeconds * 1000);

    emit(job);

    // The approver gets a COPY. It can only answer for this one job.
    const info = Object.freeze({
      id,
      code: job.code,
      risk: job.risk,
      reasons: [...job.reasons],
      cwd: job.cwd,
      command: job.command,
      argv: [...job.argv],
      timeout_s: job.timeout_s,
      expires_in_s: config.approvalTtlSeconds,
      script: job.script ? { ...job.script } : undefined
    });
    Promise.resolve()
      .then(() => approver.ask(info, { signal: job.abort.signal }))
      .then(decision => onDecision(job, decision), () => onDecision(job, "timeout"));
  }

  function onDecision(job, decision) {
    if (job.state !== "pending_approval" || job.final) return; // late, duplicate or replayed answers are ignored
    if (now() > job.approvalDeadline) return finish(job, "expired", { error: "approval window elapsed; nothing was run" });
    if (decision === "reject") return finish(job, "rejected");
    if (decision !== "approve") return finish(job, "expired", { error: "no approval received" });

    const re = revalidate(job);
    if (!re.ok) return finish(job, "blocked", { reasons: re.reasons });

    clearTimeout(job.expiryTimer);
    job.state = "approved"; // consumed: this ID can never be approved again
    job.approved_at = now();
    emit(job);
    queue.push(job);
    pump();
  }

  function pump() {
    if (running || !queue.length) return;
    const job = queue.shift();
    if (job.final || job.state !== "approved") return pump();
    const re = revalidate(job); // last check, immediately before spawning
    if (!re.ok) { finish(job, "blocked", { reasons: re.reasons }); return pump(); }
    run(job, re);
  }

  function buildEnv(job) {
    const home = path.join(config.baseReal, ".cfb-home");
    try { fs.mkdirSync(home, { recursive: true, mode: 0o700 }); } catch {}
    const env = {};
    for (const k of ENV_PASSTHROUGH) if (process.env[k] !== undefined) env[k] = process.env[k];
    Object.assign(env, {
      HOME: home,
      PWD: job.cwd,
      TERM: "dumb",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: path.join(home, ".gitconfig"),
      GIT_TERMINAL_PROMPT: "0",
      GIT_PAGER: "cat",
      PYTHONDONTWRITEBYTECODE: "1",
      npm_config_ignore_scripts: "true",
      npm_config_update_notifier: "false",
      npm_config_fund: "false",
      npm_config_userconfig: path.join(home, ".npmrc"),
      npm_config_globalconfig: path.join(home, ".npmrc-global"),
      npm_config_cache: path.join(home, ".npm"),
      npm_config_prefix: path.join(home, ".npm-global")
    });
    return env;
  }

  function killGroup(job, signal) {
    const pid = job.proc && job.proc.pid;
    if (!pid) return;
    try { process.kill(-pid, signal); } catch { try { job.proc.kill(signal); } catch {} }
  }

  function terminate(job, reason) {
    if (!job.proc || job.killReason) return;
    job.killReason = reason;
    killGroup(job, "SIGTERM");
    job.killTimer = setTimeout(() => killGroup(job, "SIGKILL"), 2000);
  }

  function run(job, re) {
    job.state = "running";
    job.started_at = now();
    running = job;
    emit(job);

    const limit = config.outputLimitBytes;
    const out = { chunks: [], bytes: 0 };
    const err = { chunks: [], bytes: 0 };
    const collect = (buf, chunk, flag) => {
      const room = limit - buf.bytes;
      if (room > 0) buf.chunks.push(chunk.subarray(0, room));
      buf.bytes += chunk.length;
      if (chunk.length > room) {
        job[flag] = true;
        terminate(job, "output_limit");
      }
    };

    const wrapped = timeoutBin ? [timeoutBin, "-k", "3", String(job.timeout_s), ...re.cl.argv] : re.cl.argv;
    let child;
    try {
      child = spawnImpl(wrapped[0], wrapped.slice(1), {
        cwd: re.cwd,
        env: buildEnv(job),
        detached: true,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (e) {
      running = null;
      finish(job, "error", { error: `could not start: ${e.message}` });
      return pump();
    }
    job.proc = child;

    // Backup timer (the `timeout` wrapper, when present, is a second line of defence
    // that also works if this agent is killed).
    job.runTimer = setTimeout(() => terminate(job, "timeout"), job.timeout_s * 1000 + (timeoutBin ? 1500 : 0));

    child.stdout.on("data", c => collect(out, c, "stdout_truncated"));
    child.stderr.on("data", c => collect(err, c, "stderr_truncated"));

    let ended = false;
    const end = ({ code, signal, error }) => {
      if (ended) return;
      ended = true;
      killGroup(job, "SIGKILL"); // sweep stragglers in the process group
      running = null;
      const extra = {
        exit_code: typeof code === "number" ? code : null,
        signal: signal || null,
        stdout: redact(Buffer.concat(out.chunks).toString("utf8")),
        stderr: redact(Buffer.concat(err.chunks).toString("utf8"))
      };
      let state = "completed";
      if (error) { state = "error"; extra.error = `process error: ${error.message}`; }
      else if (job.killReason === "timeout" || (timeoutBin && code === 124 && !job.killReason)) { state = "timed_out"; extra.timed_out = true; }
      else if (job.killReason === "output_limit") state = "output_limit";
      else if (job.killReason === "cancel") state = "cancelled";
      finish(job, state, extra);
      pump();
    };
    child.on("error", error => end({ error }));
    child.on("close", (code, signal) => end({ code, signal }));
  }

  function handleCancel(msg) {
    const id = msg && msg.command_id;
    const job = typeof id === "string" ? jobs.get(id) : undefined;
    if (!job) return;
    if (job.final) { emit(job); return; }
    if (job.state === "pending_approval" || job.state === "approved") {
      const qi = queue.indexOf(job);
      if (qi >= 0) queue.splice(qi, 1);
      finish(job, "cancelled", { error: "cancelled before it ran" });
    } else if (job.state === "running") {
      terminate(job, "cancel");
    }
  }

  function snapshotAll() {
    return [...jobs.values()].slice(-MAX_KEPT_JOBS).map(snapshot);
  }

  function shutdown() {
    for (const job of jobs.values()) {
      if (job.final) continue;
      if (job.state === "running") { job.killReason = "cancel"; killGroup(job, "SIGKILL"); }
      else finish(job, "cancelled", { error: "agent shutting down" });
    }
    if (approver && approver.close) approver.close();
  }

  return { handleRequest, handleCancel, snapshotAll, shutdown, _jobs: jobs };
}

module.exports = {
  loadConfig,
  tokenize,
  classify,
  checkPath,
  realpathLoose,
  redactSecrets,
  createExecManager,
  createTtyApprover,
  PROTECTED_SEGMENT
};
