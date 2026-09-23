# Development Guide for rt

## Quick Start

### Building
```bash
make              # Build binaries
make clean        # Clean artifacts
make install      # Install to /usr/local/bin/
```

### Testing the Daemon

Start the daemon:
```bash
./bin/rtd -p "mypassword" -s /tmp/rt-test.sock
```

In another terminal, test with the CLI:
```bash
./bin/rt -l -p "mypassword" -s /tmp/rt-test.sock
```

Or test the socket protocol directly using a simple client:
```bash
# In Python:
import socket
s = socket.socket(socket.AF_UNIX)
s.connect('/tmp/rt-test.sock')
s.send(b'AUTH:mypassword\n')
print(s.recv(1024).decode())
```

## Code Structure

### `src/rtd.c` — Main Daemon
- Listens on Unix socket
- Handles client connections in separate threads
- Processes AUTH, SHELL, CD, HIBERNATE, WAKE commands
- Spawns PTY-based shell sessions

### `src/rt.c` — CLI Client
- Connects to daemon socket
- Sends AUTH command
- Starts interactive shell for `-l` option
- Sends HIBERNATE for `-h` option

### `src/auth.c/h` — Authentication
- Password hashing with SHA256 + salt
- Failed attempt tracking
- Exponential backoff lockout

### `src/session.c/h` — Session Management
- Creates and tracks shell sessions
- PTY management
- Session lifecycle (create, destroy, change directory)
- Hibernation mode

### `src/sandbox.c/h` — Filesystem Sandboxing
- Path validation against sandbox root
- chroot enforcement for `-l` mode
- Escape-proof isolation

## Socket Protocol

Commands sent to the daemon:

```
AUTH:PASSWORD              → OK:Authenticated | ERR:Invalid password
SHELL:DIRECTORY           → OK:SESSION_ID | ERR:...
CD:SESSION_ID:PATH        → OK:Changed directory | ERR:Path not allowed
HIBERNATE                 → OK:Hibernation enabled
WAKE                       → OK:Hibernation disabled
```

## Future Improvements

### Security Enhancements
- [ ] Add optional SSL/TLS for web terminal
- [ ] Support SSH key authentication
- [ ] Add connection rate limiting
- [ ] Implement command logging and audit trail
- [ ] Add IP whitelist support

### Feature Additions
- [ ] Direct SSH server (instead of socket proxy)
- [ ] Web UI for hibernation panel
- [ ] Session history and replay
- [ ] Multiple simultaneous shell sessions per client
- [ ] File transfer support
- [ ] Environment variable inheritance control

### Robustness
- [ ] Add signal handling for graceful shutdown
- [ ] Implement timeout for idle sessions
- [ ] Add memory limits per session
- [ ] Better error messages for debugging

### Performance
- [ ] Benchmark socket throughput
- [ ] Optimize PTY buffer sizes
- [ ] Connection pooling for agents

## Platform-Specific Notes

### macOS
- Uses `util.h` for openpty (instead of pty.h)
- Uses CommonCrypto for SHA256
- Requires `sudo` for chroot in sandbox mode

### Linux
- Uses `pty.h` for openpty
- Uses libcrypto (OpenSSL) for SHA256
- chroot works as regular user in user namespaces

## Debugging

### Enable verbose output
Modify `rtd.c` to add debug logging:
```c
#define DEBUG 1
#ifdef DEBUG
fprintf(stderr, "DEBUG: %s\n", message);
#endif
```

### Monitor daemon
```bash
tail -f /tmp/rtd.log
ps aux | grep rtd
lsof -p $(pgrep rtd)
```

### Test socket connectivity
```bash
# Check if socket exists
ls -l /tmp/rt.sock

# Monitor socket activity
sudo nettop -p $(pgrep rtd)
```

### Strace/dtrace
```bash
# macOS: monitor system calls
sudo dtrace -p $(pgrep rtd) -n 'syscall:::entry { @[execname] = count(); }'

# Linux: monitor system calls
strace -p $(pgrep rtd)
```

## Architecture Notes

### Session Isolation
Each connected client gets its own thread running `handle_client()`. Sessions are stored in a thread-safe dynamic array protected by `SessionManager::lock`.

### PTY Allocation
Uses `openpty()` to create master/slave PTY pairs. The shell runs in the slave, and the daemon communicates via the master.

### Sandbox Escape Prevention
- chroot restricts filesystem to specified directory
- realpath() validates all paths before allowing access
- The sandbox is enforced at spawn time, not per-command
- All child processes inherit the chroot restriction

## Testing Checklist

- [ ] Build succeeds on macOS and Linux
- [ ] Daemon starts and listens on socket
- [ ] Client can authenticate with correct password
- [ ] Client rejected with wrong password
- [ ] Failed attempts trigger lockout
- [ ] Shell spawning works with PTY
- [ ] Directory changes work
- [ ] Hibernation mode stops sessions
- [ ] Wake mode resumes accepting connections
- [ ] Sandbox mode restricts filesystem
- [ ] Interactive shell input/output works
- [ ] Ctrl+C handling works
- [ ] Daemon graceful shutdown
