# rt

Reach this Mac's terminal from anywhere over SSH, as if it were a VPS. The other computer needs only `ssh`. Full details: `man rt`.

## Build and install

Needs Homebrew `libssh`; `cloudflared` is optional (the phone panel and the port-443 fallback route use it).

```sh
brew install libssh cloudflared
make install        # installs rt, its alias remote, and the man pages under $(brew --prefix)
```

## Use

`remote` is the same command as `rt`, with the same options.

```sh
rt                  # full access, sessions start in the current directory
rt -l               # sandbox sessions to the current directory
rt -l ~/project -h  # sandbox to ~/project and publish the phone panel
rt -k ~/.ssh/authorized_keys   # require a listed key as well as the password
rt -n               # no relay or tunnel, 127.0.0.1 only
rt -c               # send a cleanup script to the client on disconnect
rt -w ~/logs        # also append the log to ~/logs/rt.log
rt -b               # bidirectional: reach the joining client back with `peer`
rt -p               # stay reachable with the lid closed (sudo pmset, undone on exit)
```

With `-b`, join using a reverse forward and you can drive both machines from one
session — plain commands run on the Mac, `peer cmd` runs on the client:

```sh
ssh -R 127.0.0.1:0:127.0.0.1:22 -J rt-XXXXXXXX@ssh-j.com mac
# then, inside the session:
peer uname -a       # runs on the machine you joined from
```

`peer` reaches the client's own sshd through the reverse tunnel, so the client must accept that login. It logs in as the name you joined with (override with `RT_PEER_USER`), so a key the client already trusts makes `peer` passwordless. Only loopback reverse forwards are allowed, and only with `-b`.

`rt` asks for a password (12+ characters), checks each route end to end, then prints how to join:

```sh
ssh -J rt-XXXXXXXX@ssh-j.com mac                           # any computer with ssh
ssh -o "ProxyCommand=cloudflared access ssh --hostname %h" HOST   # if port 22 is blocked
```

The relay name is 8 random characters without look-alikes (no 0/o, 1/l/i), created once and kept, so the first command never changes. "administratively prohibited" from ssh means the name was mistyped or `rt` isn't running. `rt` also prints an `~/.ssh/config` entry with connection sharing, so agents can reuse a session you logged into once. The phone panel shows both commands.

## Host Claude Code for another machine (`rtc`)

`rtc` is a small launcher that hosts Claude Code on this Mac and makes it usable from any machine that joins over rt — the agent runs here, but does its work back on the machine you connect from, through `peer`.

```sh
rtc                 # connect, then run `claude` yourself
rtc -a              # auto-start claude on connect (drop straight into it)
rtc -a -h -p        # extra args after -a pass through to rt -b
```

It writes a workspace at `~/.local/state/rt/agent` with a `CLAUDE.md` that tells the agent to work on the client via `peer`, and a `.claude/settings.json` that pre-allows `Bash(peer:*)` so it doesn't hit the permission gate. Then it starts `rt -b` from that workspace. From the other machine (needs only `ssh`):

```sh
ssh -R 127.0.0.1:0:127.0.0.1:22 -J rt-XXXXXXXX@ssh-j.com mac   # the -b join command
claude                                                          # in the session
```

With `-a`, connecting runs `claude` directly (via `rt -C claude`), so you don't type anything. Claude Code runs on the Mac, rendered in your terminal, and edits/executes on your machine via `peer`. Set `RT_PEER_USER` if your login there differs; a key the client trusts makes it passwordless.

## Design

- **Processes.** One supervisor holds the password hash, the hibernation state and the panel. Each SSH connection is a freshly exec'd `rt --conn` process that asks the supervisor to check the password. It never holds the hash.
- **Login.** PBKDF2-SHA256 calibrated to ~250 ms per check. After 3 wrong passwords, logins slow down (1–60 s); after 10, they are refused for 15 minutes. SSH and the panel share the counter.
- **Routes.** The Mac dials out, so no router setup is needed. Relay: an `ssh -R` connection to the public relay ssh-j.com, which forwards the still-encrypted session (port 22 only). Cloudflare: a quick tunnel over HTTPS, which needs `cloudflared` on the client.
- **SSH.** Shells, `ssh host 'cmd'`, `ControlMaster`. No agent or X11 forwarding; forwarding is refused unless `-b` allows a single loopback reverse forward. Host key in `~/.local/state/rt/host_ed25519`.
- **Bidirectional (`-b`).** rt accepts a loopback `ssh -R` from the client and exposes it to the session as `$RT_PEER_PORT` plus a `peer` wrapper, so an agent on the Mac can run commands back on the client it came from. The reverse hop authenticates to the client's own sshd as the joining username (override with `RT_PEER_USER`; key or password). Off by default; all other forwarding stays blocked.
- **Sandbox (`-l`).** macOS Seatbelt via `sandbox-exec`. The directory is read/write, installed tools are runnable, and the rest of home is unreadable. Nothing else is writable except temp dirs. The keychain, `open`, Apple Events and launchd jobs are blocked. Sessions get `HOME=~/.local/state/rt/home`, so any tool that needs its own home logs in there once.
- **Panel (`-h`).** A phone page: hibernate or wake, change the directory, close sessions. Hibernating closes every session and refuses new ones.
- **Browser terminal (`-h`).** xterm.js over a WebSocket, with an Esc/Tab/Ctrl/arrow key bar on touch screens. Each terminal is its own `rt --web` process that the supervisor hands authenticated sockets to. The shell survives a dropped connection (phone locked, app switched) for 15 minutes, and the page reattaches and replays recent output.
- **Sleep.** `caffeinate -is` keeps the Mac awake, including with the screen locked. Lid-closed sleep needs `-p`, which runs `sudo pmset -a disablesleep 1` at startup (one sudo prompt) and restores it on exit.
