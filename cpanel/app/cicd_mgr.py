import os
import re
import json
import time
import hmac
import hashlib
import shutil
import logging
import threading
import subprocess
from datetime import datetime

# Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Data storage paths (use /var/lib/lite-cpanel/cicd if root, otherwise fallback to local/tmp)
if os.geteuid() == 0:
    CICD_DIR = '/var/lib/lite-cpanel/cicd'
else:
    CICD_DIR = os.path.join(BASE_DIR, 'data', 'cicd')

REPOS_FILE = os.path.join(CICD_DIR, 'repos.json')
KEYS_DIR = os.path.join(CICD_DIR, 'keys')
LOGS_DIR = os.path.join(CICD_DIR, 'logs')

# Global deployment locks to prevent simultaneous builds on the same repository
DEPLOYMENT_LOCKS = {}
GLOBAL_LOCK = threading.Lock()

def _ensure_directories():
    """Ensure that all required storage directories exist with secure permissions."""
    try:
        os.makedirs(CICD_DIR, exist_ok=True)
        os.makedirs(KEYS_DIR, exist_ok=True)
        os.makedirs(LOGS_DIR, exist_ok=True)
        if os.geteuid() == 0:
            os.chmod(CICD_DIR, 0o750)
            os.chmod(KEYS_DIR, 0o700)
            os.chmod(LOGS_DIR, 0o755)
    except Exception as e:
        logging.error(f"Error initializing CI/CD directories: {e}")

def get_cicd_repos():
    """Returns a dictionary of all registered CI/CD repositories."""
    _ensure_directories()
    if not os.path.exists(REPOS_FILE):
        return {}
    try:
        with open(REPOS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load repos.json: {e}")
        return {}

def get_cicd_repo(repo_id):
    """Returns configuration for a single repository, or None if not found."""
    repos = get_cicd_repos()
    return repos.get(repo_id)

def save_cicd_repo(repo_data):
    """Saves or updates a repository configuration."""
    _ensure_directories()
    with GLOBAL_LOCK:
        repos = get_cicd_repos()
        repo_id = repo_data.get('repo_id')
        if not repo_id:
            return False, "Repository ID is required."
        repos[repo_id] = repo_data
        try:
            with open(REPOS_FILE, 'w') as f:
                json.dump(repos, f, indent=4)
            if os.geteuid() == 0:
                os.chmod(REPOS_FILE, 0o600)
            return True, "Repository saved successfully."
        except Exception as e:
            return False, f"Failed to save repository config: {str(e)}"

def delete_cicd_repo(repo_id):
    """Deletes a repository configuration and removes associated deploy keys & logs."""
    _ensure_directories()
    with GLOBAL_LOCK:
        repos = get_cicd_repos()
        if repo_id not in repos:
            return False, "Repository not found."
        
        repo = repos[repo_id]
        
        # Remove deploy keys if they exist
        key_path = repo.get('deploy_key_path')
        if key_path and os.path.exists(key_path):
            try:
                os.remove(key_path)
                if os.path.exists(key_path + ".pub"):
                    os.remove(key_path + ".pub")
            except Exception:
                pass

        # Remove logs if they exist
        log_file = os.path.join(LOGS_DIR, f"deploy_{repo_id}.log")
        if os.path.exists(log_file):
            try:
                os.remove(log_file)
            except Exception:
                pass

        del repos[repo_id]
        try:
            with open(REPOS_FILE, 'w') as f:
                json.dump(repos, f, indent=4)
            return True, f"Repository {repo.get('name', repo_id)} unlinked successfully."
        except Exception as e:
            return False, f"Failed to delete repository config: {str(e)}"

def generate_deploy_key(repo_id):
    """
    Generates a dedicated SSH ed25519 keypair for a repository.
    Returns (private_key_path, public_key_content).
    """
    _ensure_directories()
    key_path = os.path.join(KEYS_DIR, f"id_deploy_{repo_id}")
    pub_path = key_path + ".pub"

    # If key already exists, read and return it
    if os.path.exists(key_path) and os.path.exists(pub_path):
        try:
            with open(pub_path, 'r') as f:
                return key_path, f.read().strip()
        except Exception:
            pass

    # Generate new ed25519 keypair (or rsa 4096 fallback)
    try:
        cmd = ['ssh-keygen', '-t', 'ed25519', '-f', key_path, '-N', '', '-C', f"lite-cpanel-deploy-{repo_id}"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            # Fallback to RSA
            cmd = ['ssh-keygen', '-t', 'rsa', '-b', '4096', '-f', key_path, '-N', '', '-C', f"lite-cpanel-deploy-{repo_id}"]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        # Set tight permissions (600 for private key, 644 for public key)
        os.chmod(key_path, 0o600)
        os.chmod(pub_path, 0o644)

        with open(pub_path, 'r') as f:
            pub_key = f.read().strip()
        return key_path, pub_key
    except Exception as e:
        logging.error(f"Failed to generate deploy key for {repo_id}: {e}")
        return None, None

def get_git_environment(repo):
    """Builds the execution environment for Git commands including SSH keys."""
    env = os.environ.copy()
    
    # Ensure system & NVM tools are reachable
    extra_paths = [
        "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
        "/root/.nvm/versions/node/v24.16.0/bin",
        "/home/tyson/.config/nvm/versions/node/v24.16.0/bin"
    ]
    # Check for any active NVM node binary
    nvm_dir = os.path.expanduser("~/.nvm")
    if os.path.exists(nvm_dir):
        versions_dir = os.path.join(nvm_dir, 'versions', 'node')
        if os.path.exists(versions_dir):
            for v in sorted(os.listdir(versions_dir), reverse=True):
                node_bin = os.path.join(versions_dir, v, 'bin')
                if os.path.exists(node_bin):
                    extra_paths.insert(0, node_bin)
                    break

    env["PATH"] = ":".join(extra_paths) + ":" + env.get("PATH", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    
    # If SSH deploy key is configured
    if repo.get('auth_type') == 'ssh':
        key_path = repo.get('deploy_key_path')
        if not key_path or not os.path.exists(key_path):
            key_path, pub_key = generate_deploy_key(repo.get('repo_id', 'default'))
            if key_path:
                repo['deploy_key_path'] = key_path
                repo['public_key'] = pub_key
                save_cicd_repo(repo)
        if key_path and os.path.exists(key_path):
            env['GIT_SSH_COMMAND'] = f"ssh -i {key_path} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

    return env

def get_deploy_logs(repo_id, max_lines=200):
    """Fetches the latest deployment log lines for a repository."""
    _ensure_directories()
    log_file = os.path.join(LOGS_DIR, f"deploy_{repo_id}.log")
    if not os.path.exists(log_file):
        return "No deployment logs recorded yet."
    try:
        with open(log_file, 'r', errors='ignore') as f:
            lines = f.readlines()
            return "".join(lines[-max_lines:])
    except Exception as e:
        return f"Error reading logs: {str(e)}"

def _append_log(log_file, message):
    """Appends a line or chunk to the deployment log file."""
    try:
        with open(log_file, 'a') as f:
            f.write(message + "\n")
    except Exception:
        pass

def _run_git_cmd(args, env=None, cwd=None):
    """Executes a git command with safe.directory configured to avoid dubious ownership errors."""
    cmd = ['git', '-c', 'safe.directory=*'] + args
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)

def run_deployment_pipeline(repo_id, triggered_by='manual'):
    """
    Executes the complete deployment pipeline for a repository:
    1. Git fetch & pull (or clone)
    2. Build & dependencies step (npm, docker compose, composer)
    3. Service reload (pm2, docker, php-fpm)
    4. Updates commit metadata and status
    """
    _ensure_directories()
    repos = get_cicd_repos()
    repo = repos.get(repo_id)
    if not repo:
        return False, "Repository not found."

    # Check lock
    if repo_id not in DEPLOYMENT_LOCKS:
        DEPLOYMENT_LOCKS[repo_id] = threading.Lock()

    if not DEPLOYMENT_LOCKS[repo_id].acquire(blocking=False):
        return False, "A deployment is already in progress for this repository."

    log_file = os.path.join(LOGS_DIR, f"deploy_{repo_id}.log")

    try:
        # Mark status as building
        start_time = time.time()
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        repo['last_status'] = 'building'
        repo['last_trigger'] = triggered_by
        save_cicd_repo(repo)

        # Clear and initialize log
        with open(log_file, 'w') as f:
            f.write(f"====================================================\n")
            f.write(f"🚀 Deployment Started: {repo.get('name', repo_id)}\n")
            f.write(f"Trigger: {triggered_by} | Branch: {repo.get('branch', 'main')}\n")
            f.write(f"Started At: {now_str}\n")
            f.write(f"====================================================\n\n")

        target_dir = os.path.abspath(repo.get('target_dir'))
        repo_url = repo.get('repo_url')
        branch = repo.get('branch', 'main')
        auth_type = repo.get('auth_type', 'public')
        app_type = repo.get('app_type', 'domain')
        env = get_git_environment(repo)

        # If token auth is used on HTTPS URL, construct authenticated remote
        effective_url = repo_url
        if auth_type == 'token' and repo.get('auth_token') and repo_url.startswith('https://'):
            token = repo.get('auth_token').strip()
            # Insert token: https://x-access-token:<token>@github.com/...
            effective_url = re.sub(r'^https://', f'https://x-access-token:{token}@', repo_url)
        elif auth_type == 'ssh' and repo_url.startswith('https://'):
            # Convert https://github.com/owner/repo(.git) -> git@github.com:owner/repo.git
            m = re.match(r'^https?://([^/]+)/(.+?)(?:\.git)?$', repo_url)
            if m:
                host, path = m.group(1), m.group(2)
                effective_url = f"git@{host}:{path}.git"

        # --- STEP 1: Git Clone or Pull ---
        _append_log(log_file, f"--- [1/3] Updating Git Source Code ---")
        os.makedirs(target_dir, exist_ok=True)

        # Configure safe.directory so git allows operations across differing user ownership (e.g. root vs www-data)
        try:
            check = _run_git_cmd(['config', '--global', '--get-all', 'safe.directory'], env=env)
            existing_safe = [line.strip() for line in (check.stdout or '').splitlines() if line.strip()]
            if '*' not in existing_safe:
                _run_git_cmd(['config', '--global', '--add', 'safe.directory', '*'], env=env)
            if target_dir not in existing_safe:
                _run_git_cmd(['config', '--global', '--add', 'safe.directory', target_dir], env=env)
            if os.geteuid() == 0:
                _run_git_cmd(['config', '--system', '--add', 'safe.directory', '*'], env=env)
        except Exception:
            pass

        git_dir = os.path.join(target_dir, '.git')

        if not os.path.exists(git_dir):
            # Check if directory is empty or only has hidden files
            dir_contents = [f for f in os.listdir(target_dir) if f not in ['.git', '.keep', 'index.html', 'default.html']]
            if len(dir_contents) == 0:
                _append_log(log_file, f"Target directory is empty. Running initial git clone from {repo_url} (branch: {branch})...")
                res = _run_git_cmd(
                    ['clone', '--branch', branch, effective_url, target_dir],
                    env=env
                )
                _append_log(log_file, res.stdout)
                if res.returncode != 0:
                    _append_log(log_file, f"Git clone failed: {res.stderr}")
                    raise Exception(f"Git clone error: {res.stderr.strip()}")
            else:
                _append_log(log_file, f"Directory contains existing files. Initializing Git repository...")
                _run_git_cmd(['init', target_dir], env=env)
                _run_git_cmd(['-C', target_dir, 'remote', 'remove', 'origin'], env=env)
                _run_git_cmd(['-C', target_dir, 'remote', 'add', 'origin', effective_url], env=env)
                res = _run_git_cmd(['-C', target_dir, 'fetch', 'origin', branch], env=env)
                _append_log(log_file, res.stdout)
                if res.returncode != 0:
                    _append_log(log_file, f"Git fetch failed: {res.stderr}")
                    raise Exception(f"Git fetch error: {res.stderr.strip()}")
                res = _run_git_cmd(['-C', target_dir, 'checkout', '-B', branch, f'origin/{branch}', '-f'], env=env)
                _append_log(log_file, res.stdout)
        else:
            _append_log(log_file, f"Fetching latest commits on branch '{branch}'...")
            # Ensure remote 'origin' exists and has the correct URL
            remotes = _run_git_cmd(['-C', target_dir, 'remote'], env=env).stdout.split()
            if 'origin' in remotes:
                _run_git_cmd(['-C', target_dir, 'remote', 'set-url', 'origin', effective_url], env=env)
            else:
                _run_git_cmd(['-C', target_dir, 'remote', 'add', 'origin', effective_url], env=env)

            res = _run_git_cmd(['-C', target_dir, 'fetch', 'origin', branch], env=env)
            _append_log(log_file, res.stdout)
            if res.returncode != 0:
                _append_log(log_file, f"Git fetch error: {res.stderr}")
                err_lower = res.stderr.lower()
                if 'could not read' in err_lower or 'not found' in err_lower or 'access rights' in err_lower or 'terminal prompts' in err_lower:
                    _append_log(log_file, "💡 Hint: For private repositories, configure an SSH Deploy Key or Personal Access Token in the Setup modal.")
                raise Exception(f"Git fetch error: {res.stderr.strip()}")

            # Checkout and pull
            res = _run_git_cmd(['-C', target_dir, 'checkout', branch], env=env)
            if res.returncode != 0:
                _run_git_cmd(['-C', target_dir, 'checkout', '-B', branch, f'origin/{branch}'], env=env)

            res = _run_git_cmd(['-C', target_dir, 'pull', 'origin', branch], env=env)
            _append_log(log_file, res.stdout)
            if res.returncode != 0:
                _append_log(log_file, f"Git pull error: {res.stderr}")
                raise Exception(f"Git pull error: {res.stderr.strip()}")

        _append_log(log_file, "✅ Git pull completed successfully.\n")

        # --- STEP 2: Application Build / Dependencies ---
        _append_log(log_file, f"--- [2/3] Running Build & Dependencies ({app_type.upper()}) ---")

        if app_type == 'nextjs':
            pkg_json = os.path.join(target_dir, 'package.json')
            if os.path.exists(pkg_json):
                # Detect package manager
                pkg_mgr = 'npm'
                if os.path.exists(os.path.join(target_dir, 'pnpm-lock.yaml')):
                    pkg_mgr = 'pnpm'
                elif os.path.exists(os.path.join(target_dir, 'yarn.lock')):
                    pkg_mgr = 'yarn'

                _append_log(log_file, f"Installing dependencies using {pkg_mgr}...")
                install_cmd = [pkg_mgr, 'install']
                res = subprocess.run(install_cmd, cwd=target_dir, capture_output=True, text=True, env=env)
                _append_log(log_file, res.stdout)
                if res.returncode != 0:
                    _append_log(log_file, f"{pkg_mgr} install warning/error: {res.stderr}")

                # Build step
                custom_build = repo.get('build_cmd')
                build_cmd = custom_build.split() if custom_build else [pkg_mgr, 'run', 'build']
                _append_log(log_file, f"Running build command: {' '.join(build_cmd)}...")
                res = subprocess.run(build_cmd, cwd=target_dir, capture_output=True, text=True, env=env)
                _append_log(log_file, res.stdout)
                if res.returncode != 0:
                    _append_log(log_file, f"Build error: {res.stderr}")
                    raise Exception(f"Build failed: {res.stderr.strip() or res.stdout.strip()}")
            else:
                _append_log(log_file, "Notice: No package.json found in target directory, skipping npm build.")

        elif app_type == 'docker':
            yml_path = os.path.join(target_dir, 'docker-compose.yml')
            yaml_path = os.path.join(target_dir, 'docker-compose.yaml')
            if os.path.exists(yml_path) or os.path.exists(yaml_path):
                _append_log(log_file, f"Running 'docker compose up -d --build' in {target_dir}...")
                res = subprocess.run(['docker', 'compose', 'up', '-d', '--build'], cwd=target_dir, capture_output=True, text=True, env=env)
                _append_log(log_file, res.stdout)
                if res.stderr:
                    _append_log(log_file, res.stderr)
                if res.returncode != 0:
                    raise Exception(f"Docker compose failed: {res.stderr.strip()}")
                
                # Cleanup dangling images
                subprocess.run(['docker', 'image', 'prune', '-f'], capture_output=True, text=True, env=env)
            else:
                _append_log(log_file, "Notice: No docker-compose.yml found in document root.")

        elif app_type in ['domain', 'php']:
            composer_json = os.path.join(target_dir, 'composer.json')
            if os.path.exists(composer_json) and shutil.which('composer'):
                _append_log(log_file, "Found composer.json. Running 'composer install --no-dev --optimize-autoloader'...")
                res = subprocess.run(['composer', 'install', '--no-dev', '--optimize-autoloader', '--no-interaction'], 
                                     cwd=target_dir, capture_output=True, text=True, env=env)
                _append_log(log_file, res.stdout)
                if res.returncode != 0:
                    _append_log(log_file, f"Composer warning: {res.stderr}")

            # Ensure proper www-data file ownership and permissions if running as root
            if os.geteuid() == 0:
                _append_log(log_file, "Fixing web file permissions (chown www-data:www-data)...")
                try:
                    subprocess.run(['chown', '-R', 'www-data:www-data', target_dir], check=True, capture_output=True)
                except Exception as e:
                    _append_log(log_file, f"Warning setting permissions: {e}")

        # Custom post-deploy script if configured
        post_deploy = repo.get('post_deploy_cmd')
        if post_deploy:
            _append_log(log_file, f"Executing custom post-deploy command: {post_deploy}...")
            res = subprocess.run(post_deploy, shell=True, cwd=target_dir, capture_output=True, text=True, env=env)
            _append_log(log_file, res.stdout)
            if res.returncode != 0:
                _append_log(log_file, f"Post-deploy warning: {res.stderr}")

        _append_log(log_file, "✅ Build step completed.\n")

        # --- STEP 3: Service Reload ---
        _append_log(log_file, f"--- [3/3] Reloading Application Services ---")
        if app_type == 'nextjs':
            pm2_name = repo.get('pm2_name') or repo.get('name')
            pm2_cmd = shutil.which('pm2') or 'pm2'
            _append_log(log_file, f"Reloading PM2 process '{pm2_name}'...")
            res = subprocess.run([pm2_cmd, 'reload', pm2_name], capture_output=True, text=True, env=env)
            if res.returncode != 0:
                # Try restart
                res = subprocess.run([pm2_cmd, 'restart', pm2_name], capture_output=True, text=True, env=env)
            _append_log(log_file, res.stdout)
            # Save PM2 state
            subprocess.run([pm2_cmd, 'save'], capture_output=True, text=True, env=env)
            _append_log(log_file, "✅ PM2 process reloaded.")

        elif app_type in ['domain', 'php']:
            _append_log(log_file, "Reloading PHP-FPM service to clear OPCache...")
            # Try reloading common PHP-FPM service names
            reloaded = False
            for ver in ['8.3', '8.2', '8.1', '8.0', '7.4']:
                srv = f"php{ver}-fpm"
                check = subprocess.run(['systemctl', 'is-active', '--quiet', srv], capture_output=True)
                if check.returncode == 0:
                    subprocess.run(['systemctl', 'reload', srv], capture_output=True)
                    _append_log(log_file, f"Reloaded {srv}.")
                    reloaded = True
                    break
            if not reloaded:
                # Fallback to reloading apache or nginx
                subprocess.run(['systemctl', 'reload', 'apache2'], capture_output=True)
                subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True)
                _append_log(log_file, "Reloaded webserver.")

        # --- STEP 4: Fetch Latest Commit Metadata ---
        commit_info = {}
        try:
            res = _run_git_cmd(
                ['-C', target_dir, 'log', '-1', '--format=%h|%an|%ad|%s', '--date=short'],
                env=env
            )
            if res.returncode == 0 and res.stdout.strip():
                parts = res.stdout.strip().split('|')
                commit_info = {
                    'hash': parts[0] if len(parts) > 0 else '',
                    'author': parts[1] if len(parts) > 1 else '',
                    'date': parts[2] if len(parts) > 2 else '',
                    'message': parts[3] if len(parts) > 3 else ''
                }
        except Exception:
            pass

        # Finalize
        duration = round(time.time() - start_time, 2)
        _append_log(log_file, f"\n====================================================")
        _append_log(log_file, f"🎉 Deployment Succeeded in {duration} seconds!")
        _append_log(log_file, f"Commit: {commit_info.get('hash', 'unknown')} - {commit_info.get('message', '')}")
        _append_log(log_file, f"Completed At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        _append_log(log_file, f"====================================================\n")

        # Update saved repo config
        repo['last_status'] = 'success'
        repo['last_deployed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        repo['last_duration'] = f"{duration}s"
        if commit_info:
            repo['last_commit'] = commit_info
        save_cicd_repo(repo)

        return True, f"Deployment completed successfully in {duration}s."

    except Exception as e:
        duration = round(time.time() - start_time, 2)
        err_msg = str(e)
        _append_log(log_file, f"\n❌ Deployment Failed: {err_msg}")
        _append_log(log_file, f"Duration: {duration} seconds")
        _append_log(log_file, f"Failed At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        _append_log(log_file, f"====================================================\n")

        repo['last_status'] = 'failed'
        repo['last_deployed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        repo['last_duration'] = f"{duration}s"
        save_cicd_repo(repo)

        return False, f"Deployment failed: {err_msg}"

    finally:
        DEPLOYMENT_LOCKS[repo_id].release()

def verify_webhook_signature(repo, request):
    """
    Validates GitHub or GitLab webhook signatures and headers.
    Returns (is_valid, reason).
    """
    secret = (repo.get('webhook_secret') or '').strip()
    if not secret:
        # If no secret configured in Lite-cPanel, allow since the token in the URL is unique
        return True, "No secret required"

    raw_data = request.get_data()

    # 1. GitHub verification: X-Hub-Signature-256 (SHA-256)
    gh_sig256 = request.headers.get('X-Hub-Signature-256', '').strip()
    if gh_sig256:
        provided = gh_sig256.split('sha256=')[-1].strip().lower()
        expected = hmac.new(secret.encode('utf-8'), raw_data, hashlib.sha256).hexdigest().lower()
        if hmac.compare_digest(expected, provided):
            return True, "Valid GitHub SHA-256 signature"
        return False, "GitHub signature mismatch"

    # 1b. Legacy GitHub verification: X-Hub-Signature (SHA-1)
    gh_sig1 = request.headers.get('X-Hub-Signature', '').strip()
    if gh_sig1:
        provided = gh_sig1.split('sha1=')[-1].strip().lower()
        expected = hmac.new(secret.encode('utf-8'), raw_data, hashlib.sha1).hexdigest().lower()
        if hmac.compare_digest(expected, provided):
            return True, "Valid GitHub SHA-1 signature"
        return False, "GitHub signature mismatch"

    # 2. GitLab verification: X-Gitlab-Token header
    gl_token = request.headers.get('X-Gitlab-Token', '').strip()
    if gl_token:
        if hmac.compare_digest(secret, gl_token):
            return True, "Valid GitLab token"
        return False, "GitLab token mismatch"

    # 3. Query string parameter fallback (?secret=...)
    query_secret = request.args.get('secret', '').strip()
    if query_secret and hmac.compare_digest(secret, query_secret):
        return True, "Valid query secret"

    # If secret is required but no matching header was provided
    return False, "Missing webhook signature or secret header"


def get_available_targets():
    """
    Scans the system to discover existing Next.js apps, Docker apps, and Domains
    that can be connected to CI/CD.
    """
    targets = []
    seen = set()

    # 1. Next.js apps
    try:
        from nextjs_mgr import get_nextjs_apps
        for app in get_nextjs_apps():
            d = app.get('domain')
            if d and d not in seen:
                targets.append({
                    'id': f"nextjs_{d}",
                    'name': f"{d} (Next.js App)",
                    'domain': d,
                    'app_type': 'nextjs',
                    'default_dir': f"/var/www/{d}",
                    'pm2_name': d
                })
                seen.add(f"nextjs_{d}")
    except Exception:
        pass

    # 2. Docker apps
    try:
        from docker_mgr import get_docker_apps
        for app in get_docker_apps():
            d = app.get('domain')
            if d and d not in seen:
                targets.append({
                    'id': f"docker_{d}",
                    'name': f"{d} (Docker App)",
                    'domain': d,
                    'app_type': 'docker',
                    'default_dir': f"/var/www/{d}",
                    'pm2_name': ''
                })
                seen.add(f"docker_{d}")
    except Exception:
        pass

    # 3. Traditional Domains / Virtual Hosts
    try:
        from domains_mgr import get_virtual_hosts
        for vh in get_virtual_hosts():
            d = vh.get('domain')
            if d and d not in seen:
                targets.append({
                    'id': f"domain_{d}",
                    'name': f"{d} (PHP / Static Web)",
                    'domain': d,
                    'app_type': 'domain',
                    'default_dir': f"/var/www/{d}",
                    'pm2_name': ''
                })
                seen.add(f"domain_{d}")
    except Exception:
        pass

    return targets

