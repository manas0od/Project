# CFB controlled command execution — design, threat model, instructions

Status: **proposal for review. Nothing here is deployed, pushed, or activated.**
Shipping this code changes nothing for Claude: the terminal tools stay invisible
until you turn them on yourself (see "Activation").

---------------------------------------------------------------------------

## 1. Architecture and request flow

```
 Claude app            Cloudflare Worker              Durable Object            Termux agent (your phone)
 ----------            -----------------              --------------            -------------------------
 terminal_execute --->  OAuth check (401 if bad)
                        flag CFB_EXEC_ENABLED=1?  --->  validate args
                        (else "Unknown tool")           store job (state=sent)
                                                        exec_request  ------------>  parse -> allowlist -> path guard
                                                                                     blocked?  --> exec_update(blocked)  (instant)
                                                        <-- exec_update(pending_approval, risk, argv)
 <-- {command_id, pending_approval,
      "you cannot approve this"}
                                                                                     PROMPT ON THE PHONE (stdin TTY):
                                                                                       id, risk, directory, exact command,
                                                                                       final argv, timeout, script hash
                                                                                     human types:  yes <4-char code>
                                                                                     re-check fingerprint -> spawn (no shell)
 terminal_status(wait) -> long-poll             <-- exec_update(running / completed + stdout, stderr, exit_code)
 <-- {state, exit_code, stdout, stderr,
      succeeded = (completed AND exit_code==0)}
```

States: `sent → pending_approval → approved → running → completed`, or one of
`blocked | rejected | expired | cancelled | timed_out | output_limit | error | lost`.
`succeeded` is true **only** for `completed` with `exit_code == 0`.

Where approval happens, and why not over MCP: **locally, on the Termux keyboard, only.**
Anything Claude can call, Claude can call to approve itself, so an MCP
`terminal_approve` tool would be no approval at all. It does not exist (a test
asserts no tool name contains approve/reject/allow). `terminal_cancel` can only
withdraw a request.

Two independent switches must both be on before anything can run:
1. Worker: `CFB_EXEC_ENABLED` = `1` (off by default; tools are hidden and calls return "Unknown tool").
2. Agent: `~/.cfb/config.json` with `exec.enabled: true`, plus a real terminal
   at the keyboard. With no TTY (nohup, background, cron) the agent refuses to
   enable execution, because there is nobody to ask.

## 2. Threat model

| # | Threat | Controls | Residual risk |
|---|--------|----------|---------------|
| T1 | Claude is manipulated (prompt injection from a web page, file or email it read) into running something harmful | Human approves every exact command; allowlist; no shell; path guard; risk labels; "BLOCKED, don't work around it" guidance to Claude | **You rubber-stamping.** An approved `node`/`python`/`npm run` is arbitrary code |
| T2 | Attacker obtains a valid OAuth token | Cannot approve anything; max 5 pending; login password still guards new tokens | They can spam prompts and craft convincing-looking commands |
| T3 | Attacker obtains `BRIDGE_TOKEN` | Cannot execute on your phone (approval is local). A rogue agent replaces yours, so you see "Disconnected 4001" | They can read commands Claude sends and forge outputs (feeding Claude false data). Rotate the token |
| T4 | Worker, Cloudflare or GitHub account compromised | Approval and policy live in the agent, not the Worker, so a malicious Worker still needs your keystroke per command | Same as T1 |
| T5 | Output or command text that fakes the approval prompt | Command shown as JSON (escaped), control characters replaced; command output is never printed to your terminal | — |
| T6 | Symlink / `../` escapes, TOCTOU | `realpath` incl. dangling links; roots limited to `~/cfb`; everything re-validated immediately before spawn; scripts run by absolute real path and hash-pinned | Tiny race window between check and spawn |
| T7 | Runaway or orphaned processes | Timeout (agent timer + `timeout` wrapper if present), output cap kills the process, own process group, group swept after exit, children killed on agent shutdown; serial execution | A hard kill of the agent (SIGKILL/OOM) leaves children until the `timeout` wrapper expires them; without the wrapper they could run on |
| T8 | Credentials leaking to Claude | Token/credential file names blocked for file tools; child env is whitelisted; child `HOME` is `~/cfb/.cfb-home`; bridge token redacted from output | See limitations 2 and 3 |

Why not "block dangerous strings": a string filter must out-guess a shell
(quoting, `$IFS`, `${x:0:1}`, base64, aliases, subshells, globbing) and loses.
The design removes the shell instead: the command is tokenized, shell syntax is
**refused**, and the program is started directly with an argument array. What is
left is a small allowlist where each program has its own option and path rules.

## 3. Honest limitations (please read)

1. **This is not a sandbox.** Android without root offers none. An approved
   script runs with all your Termux user's rights. The human is the boundary.
2. Approved code can read `~/.cfb/bridge.token` (same user). I cannot prevent
   that. If you ever approve something you did not fully understand, rotate `BRIDGE_TOKEN`.
3. The "protected names" list (`.env`, `*.pem`, `.npmrc`, `.git`, ...) is a
   denylist. A secret stored as `settings.json` in `~/cfb` is readable with `cat`.
   Keep secrets out of `~/cfb`. Whatever `cat` returns goes to Claude (Anthropic).
4. The script hash pins the entry file only, not modules it imports or `node_modules`.
   `view` shows the first 60 lines. Script arguments are not path-checked.
5. `npm run`/`npm test` run project-defined scripts; `npm install` downloads
   packages (lifecycle scripts are disabled via env, but their code can run later).
6. Git network commands (`clone fetch pull push remote`), `git config`, and
   `reset --hard` are blocked in this version. No pipes, redirects or globs.
7. Approval needs you on the phone, in the Termux session, within 120 s.
   Android may kill a backgrounded Termux (use `termux-wake-lock`). **Not tested on a real phone.**
8. Not implemented, recommended next: a separate OAuth scope for execution
   (`mcp:exec`), and Node's permission model (`node --permission`) for scripts.
   I could not verify the exact flags for Node 26.13, so I did not ship it blind.
9. `/request` and `/do-status` are unchanged. `/request` cannot start commands
   (tested), but it still accepts the agent token for status/echo.

## 4. Status

| Item | State |
|------|-------|
| Tools `terminal_execute`, `terminal_status`, `terminal_cancel` | Implemented, tested |
| Approval enforced by agent, bound to exact argv + directory + timeout + script hash, single use, expiry | Implemented, tested (unit + real PTY) |
| Working-directory and path restrictions incl. symlinks | Implemented, tested |
| Allowlist, no-shell parsing, 104 dangerous-command cases | Implemented, tested |
| Timeout, output limit, exit code, cancellation, duplicate ids, orphan cleanup | Implemented, tested |
| Reconnect / restart / lost-response handling | Implemented, tested (in-process and real WebSocket) |
| Secret redaction, env scrubbing | Implemented, tested |
| OAuth login/consent fix and OAuth config | Untouched, re-tested (18/18) |
| Needs your configuration | `~/.cfb/config.json`, `~/cfb/proj`, Worker flag |
| **Not tested** | Real Android/Termux (32-bit ARM, Node 26.13), the Claude app's tool UI and tool-list refresh, GitHub Actions deploy, your live Worker |

What was actually run (in my own Linux sandbox, Node 22, never on your device):
63 unit/loopback tests; 18 deliberate regressions injected to check the tests
fail when protections are removed (all 18 caught); a 34-check end-to-end run
(real Worker + Durable Object + OAuth + MCP + real agent on a pseudo-terminal);
the 18-scenario OAuth suite.

## 5. Running the tests

On the phone (Termux), from the repo folder, no extra packages needed:
```
node --test test/*.test.js
```
Expect: `# tests 63`, `# pass 63`, `# fail 0` (about 8 s on my Linux sandbox; a phone will be slower, allow a minute). They create a temp
folder, run only harmless commands (echo/touch/sleep/node scripts they write)
and delete it. They never touch your real `~/cfb`.

`test/e2e.mjs` needs a Linux PC with root; it cannot run on the phone.

## 6. Putting it on GitHub safely (website only)

Your workflow deploys on every push to `main` **and** from the "Run workflow"
button. So:
1. On github.com open the repo, tap **Add file → Create new file**, name it
   `src/exec-protocol.js`, paste the file, then at the bottom choose
   **Create a new branch** (name: `exec-review`) and commit. Nothing deploys.
2. Switch to branch `exec-review` (branch selector) and repeat for
   `termux/agent-exec.js`, `termux/agent.js`, `termux/package.json`,
   `test/helpers.js`, `test/agent-exec.test.js`, `test/exec-protocol.test.js`,
   `test/e2e.mjs`, `docs/EXEC-DESIGN.md`. For existing files (`src/index.js`,
   `package.json`) open the file, tap the pencil, select all, paste, commit to the branch.
3. Do **not** press "Run workflow" with `exec-review` selected, and do not merge
   to `main` until you have reviewed and tested.
4. When you approve: open a Pull Request from `exec-review`, merge it. Actions deploys.
   Deploying still does not enable commands.

## 7. Testing and updating the agent in Termux

First test without touching your running agent (nothing is installed outside this folder):
```
mkdir -p ~/cfb-review && cd ~/cfb-review
# put the files here (unzip cfb-exec-review.zip, or download from your branch)
node --test test/*.test.js
```
Update the agent only after you have reviewed the code:
```
cd ~/ws-test                       # your current agent folder
cp agent.js agent.js.bak           # rollback copy
cp ~/cfb-review/termux/agent.js ~/cfb-review/termux/agent-exec.js .
node agent.js
```
With no `~/.cfb/config.json` it prints `Command execution: DISABLED (no config file ...)`
and behaves exactly like today (status, echo, heartbeat).

## 8. Activation (only after you have reviewed and approved)

1. Termux: `mkdir -p ~/cfb/proj` then create `~/.cfb/config.json`:
```json
{ "exec": { "enabled": true, "roots": ["~/cfb"], "default_cwd": "~/cfb/proj" } }
```
   Optional keys: `max_timeout_seconds` (300), `approval_ttl_seconds` (120),
   `output_limit_bytes` (20000, max 49152), `max_pending` (5), `use_timeout_wrapper` (true).
2. Run `node agent.js` **in an interactive Termux session** and keep it open.
   Expect `Command execution: ENABLED (workspace roots: ...)`.
3. Cloudflare dashboard → Workers → claude-freedom-bridge → Settings →
   Variables and Secrets → add a **Secret** named `CFB_EXEC_ENABLED` with value `1`.
   (A secret survives deploys; a plain variable could be wiped by `wrangler deploy`.)
4. In Claude: refresh/reconnect the connector so it re-reads the tool list
   (**untested**: how the app caches tools).

Kill switches, fastest first: stop the agent (Ctrl+C), set `exec.enabled` to
`false`, or delete the `CFB_EXEC_ENABLED` secret (tools vanish immediately).

## 9. Rollback

* Worker: GitHub → the merged pull request → **Revert** → merge the revert PR
  (Actions redeploys the old code). Or Cloudflare dashboard → Workers →
  Deployments → roll back to the previous version. No Durable Object class,
  migration or binding changed, so rolling back is safe. Leftover `job:` records
  in Durable Object storage are ignored by the old code.
* Agent: `cd ~/ws-test && cp agent.js.bak agent.js && rm agent-exec.js`.
* Delete the secret `CFB_EXEC_ENABLED` and `~/.cfb/config.json` if you want to be certain nothing can run.

## 10. Extending the allowlist

Add a program only by editing `SIMPLE` in `termux/agent-exec.js`, with its own
option and path rules, and add a test. There is intentionally no config switch
for "allow everything".
