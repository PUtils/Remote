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
```

`rt` asks for a password (12+ characters), checks each route end to end, then prints how to join:

```sh
ssh -J rt-XXXXXXXX@ssh-j.com mac                           # any computer with ssh
ssh -o "ProxyCommand=cloudflared access ssh --hostname %h" HOST   # if port 22 is blocked
```

The relay name is 8 random characters without look-alikes (no 0/o, 1/l/i), created once and kept, so the first command never changes. "administratively prohibited" from ssh means the name was mistyped or `rt` isn't running. `rt` also prints an `~/.ssh/config` entry with connection sharing, so agents can reuse a session you logged into once. The phone panel shows both commands.

## Design

- **Processes.** One supervisor holds the password hash, the hibernation state and the panel. Each SSH connection is a freshly exec'd `rt --conn` process that asks the supervisor to check the password. It never holds the hash.
- **Login.** PBKDF2-SHA256 calibrated to ~250 ms per check. After 3 wrong passwords, logins slow down (1–60 s); after 10, they are refused for 15 minutes. SSH and the panel share the counter.
- **Routes.** The Mac dials out, so no router setup is needed. Relay: an `ssh -R` connection to the public relay ssh-j.com, which forwards the still-encrypted session (port 22 only). Cloudflare: a quick tunnel over HTTPS, which needs `cloudflared` on the client.
- **SSH.** Shells, `ssh host 'cmd'`, `ControlMaster`. No port, agent or X11 forwarding. Host key in `~/.local/state/rt/host_ed25519`.
- **Sandbox (`-l`).** macOS Seatbelt via `sandbox-exec`. The directory is read/write, installed tools are runnable, and the rest of home is unreadable. Nothing else is writable except temp dirs. The keychain, `open`, Apple Events and launchd jobs are blocked. Sessions get `HOME=~/.local/state/rt/home`, so Claude Code logs in once there, or gets a token via `ssh -o SendEnv=CLAUDE_CODE_OAUTH_TOKEN`.
- **Panel (`-h`).** A phone page: hibernate or wake, change the directory, close sessions. Hibernating closes every session and refuses new ones.
- **Browser terminal (`-h`).** xterm.js over a WebSocket, with an Esc/Tab/Ctrl/arrow key bar on touch screens. Each terminal is its own `rt --web` process that the supervisor hands authenticated sockets to. The shell survives a dropped connection (phone locked, app switched) for 15 minutes, and the page reattaches and replays recent output.
- **Sleep.** `caffeinate -is` keeps the Mac awake, including with the screen locked. Lid-closed needs `sudo pmset -a disablesleep 1`.
