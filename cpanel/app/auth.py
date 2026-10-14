import os
import pwd
from functools import wraps

try:
    from flask import session, redirect, url_for, flash, request
except ImportError:
    session = redirect = url_for = flash = request = None

# Optional imports for system authentication
try:
    import pam
except ImportError:
    pam = None

try:
    import spwd
except ImportError:
    spwd = None

try:
    import crypt
except ImportError:
    crypt = None


def _verify_crypt(password, hashed_password):
    """
    Verify password against a crypt-style hash ($6$, $y$, etc.).
    Uses stdlib crypt if available (Python < 3.13), otherwise falls back
    to libcrypt via ctypes.
    """
    if crypt is not None:
        try:
            return crypt.crypt(password, hashed_password) == hashed_password
        except Exception:
            pass

    # Fallback to C crypt(3) via ctypes (libcrypt.so)
    try:
        import ctypes
        import ctypes.util
        lib_name = ctypes.util.find_library('crypt') or 'libcrypt.so.1'
        lib = ctypes.CDLL(lib_name)
        lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.crypt.restype = ctypes.c_char_p
        res = lib.crypt(password.encode('utf-8'), hashed_password.encode('utf-8'))
        if res:
            return res.decode('utf-8', 'ignore') == hashed_password
    except Exception:
        pass

    return False


def _get_shadow_hash(username):
    """
    Retrieve the hashed password for a user from /etc/shadow.
    Uses spwd if available (Python < 3.13), or reads /etc/shadow directly
    when running with root privileges.
    """
    if spwd is not None:
        try:
            return spwd.getspnam(username).sp_pwdp
        except KeyError:
            return None
        except Exception:
            pass

    # Direct /etc/shadow lookup (requires root / euid == 0)
    try:
        with open('/etc/shadow', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if parts and parts[0] == username and len(parts) > 1:
                    return parts[1]
    except Exception:
        pass

    return None


def check_system_password(username, password):
    """
    Check if the provided username and password match a local system user (like root).
    Note: The script must run with root privileges to authenticate system users.
    Supports PAM (python-pam) as primary method as well as direct shadow/libcrypt verification,
    maintaining compatibility across Python 3.10-3.13+.
    """
    try:
        # For development purposes, if running as a non-root user and we just want to test
        # We'll allow a fallback admin/password login or simply check if not root.
        if os.geteuid() != 0:
            if username == 'admin' and password == 'password':
                return True
            return False

        # 1. Primary method: PAM authentication (recommended for Python 3.13+ per PEP 594)
        if pam is not None:
            try:
                p = pam.pam() if hasattr(pam, 'pam') else pam
                if p.authenticate(username, password, service='login', resetcreds=False):
                    return True
                for srv in ('common-auth', 'passwd', 'su'):
                    if os.path.exists(f'/etc/pam.d/{srv}'):
                        if p.authenticate(username, password, service=srv, resetcreds=False):
                            return True
            except Exception:
                pass

        # 2. Fallback method: Shadow database & crypt verification
        hashed_password = _get_shadow_hash(username)
        if hashed_password and _verify_crypt(password, hashed_password):
            return True

    except KeyError:
        # User not found
        pass
    except PermissionError:
        # Cannot read shadow file or insufficient permissions
        pass
    except Exception:
        pass

    return False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session or not session.get('logged_in'):
            if redirect and url_for:
                return redirect(url_for('login', next=request.url if request else None))
            return ("Unauthorized", 401)
        return f(*args, **kwargs)
    return decorated_function

