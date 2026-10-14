import subprocess
import json
import os
import shutil

PM2_HOME = "/root/.pm2"

def is_pm2_installed():
    """Checks if PM2 is available in the system path."""
    return shutil.which('pm2') is not None

def setup_pm2_startup():
    """Configures PM2 to start on system boot."""
    if not is_pm2_installed():
        return False, "PM2 is not installed."
        
    try:
        env = os.environ.copy()
        env["PM2_HOME"] = PM2_HOME
        pm2_cmd = get_pm2_cmd()
        
        # Run pm2 startup to generate the command
        result = subprocess.run([pm2_cmd, 'startup'], capture_output=True, text=True, env=env)
        
        startup_cmd = None
        for line in result.stdout.split('\n'):
            if 'env PATH=' in line:
                startup_cmd = line.strip()
                if startup_cmd.startswith('sudo '):
                    startup_cmd = startup_cmd[5:]
                break
                
        if startup_cmd:
            subprocess.run(startup_cmd, shell=True, check=True, env=env, capture_output=True)
            subprocess.run([pm2_cmd, 'save'], check=True, env=env, capture_output=True)
            return True, "PM2 startup configured successfully."
        elif "already" in result.stdout.lower() or "configured" in result.stdout.lower():
            subprocess.run([pm2_cmd, 'save'], check=True, env=env, capture_output=True)
            return True, "PM2 startup is already configured."
        else:
            # Fallback to direct invocation if parsing fails
            subprocess.run([pm2_cmd, 'startup', 'systemd', '-u', 'root', '--hp', '/root'], check=True, env=env, capture_output=True)
            subprocess.run([pm2_cmd, 'save'], check=True, env=env, capture_output=True)
            return True, "PM2 startup configured via fallback."
            
    except Exception as e:
        return False, f"Error configuring PM2 startup: {str(e)}"

def install_pm2():
    """Installs PM2 globally via npm using NVM."""
    try:
        bash_cmd = 'source /root/.nvm/nvm.sh && npm install pm2 -g'
        subprocess.run(['bash', '-c', bash_cmd], check=True, capture_output=True, text=True)
        setup_pm2_startup()
        return True, "PM2 installed successfully."
    except subprocess.CalledProcessError as e:
        return False, f"Error installing PM2: {e.stderr.strip()}"

def get_pm2_cmd():
    pm2_path = shutil.which('pm2')
    return pm2_path if pm2_path else 'pm2'

def list_processes():
    """Returns a list of running PM2 processes in JSON format."""
    if not is_pm2_installed():
        return []
    
    try:
        env = os.environ.copy()
        env["PM2_HOME"] = PM2_HOME
        result = subprocess.run([get_pm2_cmd(), 'jlist'], capture_output=True, text=True, check=True, env=env)
        return json.loads(result.stdout)
    except Exception:
        return []

def manage_process(action, name_or_id):
    """
    Performs an action (start, stop, restart, delete) on a PM2 process.
    """
    if action not in ['start', 'stop', 'restart', 'delete']:
        return False, "Invalid action."
    
    try:
        env = os.environ.copy()
        env["PM2_HOME"] = PM2_HOME
        subprocess.run([get_pm2_cmd(), action, str(name_or_id)], check=True, capture_output=True, text=True, env=env)
        return True, f"Process {action}ed successfully."
    except subprocess.CalledProcessError as e:
        return False, f"Error: {e.stderr.strip()}"

def start_nextjs_app(app_path, app_name, port):
    """
    Starts a Next.js application using PM2.
    Prevents duplicate processes by checking if a process with the same name
    is already registered in PM2 before attempting to start a new one.
    """
    if not os.path.exists(app_path):
        return False, f"Path does not exist: {app_path}"

    # --- Duplicate guard ---
    # Check if a PM2 process with this name already exists to prevent spawning duplicates.
    existing = list_processes()
    for proc in existing:
        if proc.get('name') == app_name:
            return False, (
                f"A process named '{app_name}' is already registered in PM2 "
                f"(ID: {proc.get('pm_id')}, status: {proc.get('pm2_env', {}).get('status', 'unknown')}). "
                "Use Restart or delete it first before starting a new instance."
            )

    try:
        env = os.environ.copy()
        env["PM2_HOME"] = PM2_HOME
        
        # Check for ecosystem.config.js (Prioritize)
        ecosystem_path = os.path.join(app_path, 'ecosystem.config.js')
        if os.path.exists(ecosystem_path):
            cmd = [get_pm2_cmd(), 'start', 'ecosystem.config.js', '--name', app_name]
        else:
            # Check if it's a standard next.js app (has package.json)
            pkg_json = os.path.join(app_path, 'package.json')
            if not os.path.exists(pkg_json):
                return False, "No package.json or ecosystem.config.js found in the specified path."
            
            # Command to start: npm start -- -p PORT
            if not port:
                return False, "Port is required when no ecosystem.config.js is found."
            
            cmd = [
                get_pm2_cmd(), 'start', 'npm', 
                '--name', app_name, 
                '--', 'start', '--', '-p', str(port)
            ]
        
        subprocess.run(cmd, cwd=app_path, check=True, capture_output=True, text=True, env=env)
        # Save to ensure it persists across reboots
        subprocess.run([get_pm2_cmd(), 'save'], check=True, env=env)
        
        return True, f"Application '{app_name}' started successfully."
    except subprocess.CalledProcessError as e:
        return False, f"Failed to start app: {e.stderr.strip()}"

def run_npm_command(app_path, command):
    """
    Runs an npm command (install or build) in the specified directory.
    """
    if command not in ['install', 'run build']:
        return False, "Invalid npm command."
    
    if not os.path.exists(app_path):
        return False, f"Path does not exist: {app_path}"
    
    try:
        # We use a longer timeout for builds
        cmd = ['npm'] + command.split()
        result = subprocess.run(cmd, cwd=app_path, capture_output=True, text=True, check=True)
        return True, f"npm {command} completed successfully."
    except subprocess.CalledProcessError as e:
        return False, f"npm {command} failed: {e.stderr.strip() or e.stdout.strip()}"
    except Exception as e:
        return False, f"An error occurred: {str(e)}"

def get_process_logs(name, lines=100):
    """Fetches the latest logs for a specific process."""
    try:
        # pm2 logs --lines N --nostream name
        result = subprocess.run([get_pm2_cmd(), 'logs', name, '--lines', str(lines), '--nostream'], 
                                capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        return f"Error fetching logs: {str(e)}"
