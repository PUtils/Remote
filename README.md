# rt

Reach this Mac's terminal from anywhere over SSH, as if it were a VPS. The other computer needs only `ssh`. Full details: `man rt`.

## Build and install

Needs Homebrew `libssh`; `cloudflared` is optional (the phone panel and the port-443 fallback route use it).

```sh
brew install libssh cloudflared
make install        # installs rt and its man page under $(brew --prefix)
```

## Use

```sh
rt                  # full access, sessions start in the current directory
rt -l               # sandbox sessions to the current directory
rt -l ~/project -h  # sandbox to ~/project and publish the phone panel
rt -k ~/.ssh/authorized_keys   # require a listed key as well as the password
rt -n               # no relay or tunnel, 127.0.0.1 only
```

`rt` asks for a password (12+ characters), checks each route end to end, then prints how to join:

```sh
ssh -J rt-XXXXXXXXXXXXXXXX@ssh-j.com rt-XXXXXXXXXXXXXXXX     # any computer with ssh
ssh -o "ProxyCommand=cloudflared access ssh --hostname %h" HOST   # if port 22 is blocked
```

The relay name is random, created once and kept, so the first command never changes. `rt` also prints an `~/.ssh/config` entry with connection sharing, so agents can reuse a session you logged into once. The phone panel shows both commands.

## Design

- **Processes.** One supervisor holds the password hash, the hibernation state and the panel. Each SSH connection is a freshly exec'd `rt --conn` process that asks the supervisor to check the password. It never holds the hash.
- **Login.** PBKDF2-SHA256 calibrated to ~250 ms per check. After 3 wrong passwords, logins slow down (1–60 s); after 10, they are refused for 15 minutes. SSH and the panel share the counter.
- **Routes.** The Mac dials out, so no router setup is needed. Relay: an `ssh -R` connection to the public relay ssh-j.com, which forwards the still-encrypted session (port 22 only). Cloudflare: a quick tunnel over HTTPS, which needs `cloudflared` on the client.
- **SSH.** Shells, `ssh host 'cmd'`, `ControlMaster`. No port, agent or X11 forwarding. Host key in `~/.local/state/rt/host_ed25519`.
- **Sandbox (`-l`).** macOS Seatbelt via `sandbox-exec`. The directory is read/write, installed tools are runnable, and the rest of home is unreadable. Nothing else is writable except temp dirs. The keychain, `open`, Apple Events and launchd jobs are blocked. Sessions get `HOME=~/.local/state/rt/home`, so Claude Code logs in once there, or gets a token via `ssh -o SendEnv=CLAUDE_CODE_OAUTH_TOKEN`.
- **Panel (`-h`).** A phone page: hibernate or wake, change the directory, close sessions. Hibernating closes every session and refuses new ones.
- **Sleep.** `caffeinate -is` keeps the Mac awake, including with the screen locked. Lid-closed needs `sudo pmset -a disablesleep 1`.

Not done yet: the browser terminal (xterm.js is vendored in `web/vendor`).
