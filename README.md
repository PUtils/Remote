# rt — Remote Terminal

A secure remote terminal utility for accessing your Mac from anywhere via SSH, browser terminal, and web control panels. Act like a VPS under your own control.

## Features

- **Multiple Access Methods**
  - SSH through Cloudflare tunnel
  - Browser-based web terminal (via xterm.js)
  - Agent-based command execution for Claude Code and other tools
  - `ssh host 'cmd'` execution for remote script running

- **Security**
  - Password-based authentication with bcrypt-like hashing
  - Exponential backoff on failed attempts (5 attempts max, 30-second lockout)
  - Separate process isolation for each connection
  - Optional filesystem sandboxing with chroot

- **Session Management**
  - PTY allocation for interactive shells
  - UUID-based session identification
  - Per-session working directory control
  - Hibernation mode to pause all remote access

- **Hibernation Control**
  - Phone-accessible web panel for hibernation control
  - Works when screen is locked
  - Optional: works when laptop is closed (with manual configuration)
  - Instantly closes all sessions and refuses new requests

- **Sandboxing for Claude Code**
  - Run Claude Code on machines without installation
  - Directory-scoped execution via `-l` option
  - Full access to system tools within sandbox
  - Escape-proof isolation

## Building

### Requirements
- macOS 10.12+ or Linux with POSIX support
- Clang/GCC compiler
- pthread library
- CommonCrypto (macOS) or libcrypto (Linux)

### Compile
```bash
make
```

This produces:
- `bin/rtd` — The daemon
- `bin/rt` — The client CLI

### Install
```bash
make install
```

This installs to `/usr/local/bin/`. Requires write permission.

## Usage

### Start the Daemon

```bash
# Basic daemon with password protection
rtd -p "your_secure_password"

# Daemon with sandbox to a directory
rtd -p "password" -l /home/user/myproject

# Custom socket location
rtd -p "password" -s /tmp/rt-custom.sock
```

### Connect with Client

```bash
# Interactive shell in current directory
rt -l -p "password"

# Interactive shell in specific directory (sandboxed)
rt -l /path/to/project -p "password"

# Access hibernation control panel
rt -h -p "password"
```

### SSH Access Through Cloudflare Tunnel

1. Install [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-applications/install-and-setup/installation/)

2. Start a tunnel to the daemon socket:
```bash
cloudflared tunnel --url unix:///tmp/rt.sock
```

3. Connect via SSH from another machine:
```bash
ssh -o ProxyUseFdpass=no user@your-tunnel-url.trycloudflare.com
```

## Architecture

### Daemon (rtd)

The server process that:
- Listens on a Unix socket
- Authenticates all incoming connections
- Spawns isolated shell sessions in PTYs
- Manages hibernation state
- Enforces sandbox restrictions

### Client (rt)

Command-line tool to:
- Connect to the daemon
- Authenticate with password
- Start interactive shells
- Control hibernation from phone/web

### Web Terminal

Uses vendored xterm.js for browser-based terminal access:
- Sends keystrokes to daemon
- Displays shell output
- Maintains session state

## Security Considerations

### Password Storage
Passwords are hashed with SHA256 + salt, stored only as hashes. They cannot be recovered.

### Failed Attempts
After 5 failed authentication attempts, the daemon locks out for 30 seconds. Subsequent attempts during lockout are rejected immediately.

### Isolation
- Each SSH connection runs in its own process
- File descriptor limits and process isolation via OS
- Use `-l DIRECTORY` for additional chroot-based filesystem isolation

### Transport Security
The daemon requires external encryption:
- Use Cloudflare tunnel for encrypted tunnel
- SSH protocol encryption for remote access
- Do not expose the socket directly to untrusted networks

### Hibernation
Use hibernation when:
- Closing the laptop
- Locking the screen
- Pausing all remote access

## Command Protocol

The daemon communicates via Unix socket with text commands:

```
AUTH:PASSWORD          # Authenticate (required first)
SHELL:DIRECTORY        # Create shell session
CD:SESSION_ID:PATH     # Change directory for session
HIBERNATE              # Enable hibernation mode
WAKE                   # Disable hibernation mode
```

## Future Enhancements

- [ ] SSH server implementation (instead of socket-based)
- [ ] Web control panel for hibernation
- [ ] Key file authentication in addition to password
- [ ] Session history and logging
- [ ] SSH agent forwarding support
- [ ] Multi-user support with per-user directories
- [ ] TLS encryption for web terminal
- [ ] Rate limiting and DDoS protection

## Files

```
├── src/
│   ├── rtd.c          # Main daemon
│   ├── rt.c           # CLI client
│   ├── auth.c/h       # Authentication & password hashing
│   ├── session.c/h    # Session management
│   └── sandbox.c/h    # Filesystem sandboxing
├── man/
│   ├── rt.1           # rt man page
│   └── rtd.1          # rtd man page
├── web/
│   └── vendor/        # Vendored xterm.js
├── Makefile
└── README.md
```

## Man Pages

```bash
man rt
man rtd
```

## Development

### Building with Debug Symbols
```bash
make CFLAGS="-Wall -Wextra -g -std=c99 -D_POSIX_C_SOURCE=200809L"
```

### Cleaning Build Artifacts
```bash
make clean
```

## License

Part of the PUtils suite. Private repository.
