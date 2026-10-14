import os
import subprocess

def get_virtual_hosts(include_docker_domains=False):
    """
    Returns a list of dictionaries with virtual host information, grouped by domain.
    Checks both Nginx and Apache directories.

    Args:
        include_docker_domains: When True, domains marked with # DOCKER_APP are
                                included in the result (useful for directory selects
                                like FTP where container web roots are needed).
                                Next.js app domains (# NEXTJS_APP) are always filtered
                                out of such selects.
                                When False (default), both # DOCKER_APP and # NEXTJS_APP
                                domains are removed so they don't appear on the generic
                                Domains management page.
    """
    grouped_vhosts = {}

    nginx_dir = '/etc/nginx/sites-available'
    if os.path.exists(nginx_dir):
        for f in os.listdir(nginx_dir):
            if f not in ['default', 'default-modsecurity.conf']:
                enabled = os.path.exists(f'/etc/nginx/sites-enabled/{f}')
                domain = f
                if domain not in grouped_vhosts:
                    grouped_vhosts[domain] = {
                        'domain': domain, 
                        'servers': [], 
                        'enabled': enabled, 
                        'config_paths': {}, 
                        'has_ssl': False
                    }
                grouped_vhosts[domain]['servers'].append('Nginx')
                grouped_vhosts[domain]['config_paths']['Nginx'] = os.path.join(nginx_dir, f)
                grouped_vhosts[domain]['enabled'] = grouped_vhosts[domain]['enabled'] or enabled

    # Check Apache
    apache_dir = '/etc/apache2/sites-available'
    if os.path.exists(apache_dir):
        for f in os.listdir(apache_dir):
            if f not in ['000-default.conf', 'default-ssl.conf', 'default-modsecurity.conf']:
                domain = f.replace('.conf', '')
                enabled = os.path.exists(f'/etc/apache2/sites-enabled/{f}')
                if domain not in grouped_vhosts:
                    grouped_vhosts[domain] = {
                        'domain': domain, 
                        'servers': [], 
                        'enabled': enabled, 
                        'config_paths': {}, 
                        'has_ssl': False
                    }
                grouped_vhosts[domain]['servers'].append('Apache')
                grouped_vhosts[domain]['config_paths']['Apache'] = os.path.join(apache_dir, f)
                grouped_vhosts[domain]['enabled'] = grouped_vhosts[domain]['enabled'] or enabled

    # Check SSL
    for domain in grouped_vhosts:
        if os.path.exists(f'/etc/letsencrypt/live/{domain}/fullchain.pem'):
            grouped_vhosts[domain]['has_ssl'] = True

    # Next.js / Docker App Filtering
    # Always filter out Next.js app domains from any non-Domains-page context.
    # Docker app domains are only shown when include_docker_domains=True (e.g. FTP
    # directory select needs the container web root paths).
    domains_to_remove = []
    for domain, data in grouped_vhosts.items():
        for server, path in data['config_paths'].items():
            try:
                with open(path, 'r') as f:
                    content = f.read()
                    is_nextjs = '# NEXTJS_APP' in content
                    is_docker = '# DOCKER_APP' in content
                    # Remove if it's a Next.js app, OR if it's a Docker app but
                    # the caller hasn't asked for Docker domains.
                    if is_nextjs or (is_docker and not include_docker_domains):
                        domains_to_remove.append(domain)
                        break
            except Exception:
                pass

    for domain in domains_to_remove:
        del grouped_vhosts[domain]

    return list(grouped_vhosts.values())

def add_virtual_host(domain):
    """
    Calls the existing vhost-manager.sh script to create a new virtual host.
    """
    # Try to find the script in the scripts directory
    script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'scripts', 'web-stack-installer.sh')

    if os.path.exists(script_path):
        try:
            # Provide an explicit environment with guaranteed standard PATH to prevent 'command not found' errors
            env = os.environ.copy()
            env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:" + env.get("PATH", "")
            
            # We assume it's run as root, so we just execute it directly
            result = subprocess.run(['/bin/bash', script_path, domain],
                                  capture_output=True, text=True, check=True, env=env)
            return True, "Virtual host created successfully."
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() if e.stderr else e.stdout.strip()
            return False, f"Error creating virtual host: {err_msg}"
    else:
        # Fallback if the script isn't found
        return False, "vhost-manager.sh script not found."

def toggle_virtual_host(domain, enable):
    """
    Enables or disables a virtual host across all installed web servers.
    """
    successes = []
    errors = []

    # Check Nginx
    nginx_avail = f'/etc/nginx/sites-available/{domain}'
    if os.path.exists(nginx_avail):
        try:
            enabled_link = f'/etc/nginx/sites-enabled/{domain}'
            if enable and not os.path.exists(enabled_link):
                os.symlink(nginx_avail, enabled_link)
            elif not enable and os.path.exists(enabled_link):
                os.remove(enabled_link)
            subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
            successes.append("Nginx")
        except Exception as e:
            errors.append(f"Nginx: {str(e)}")

    # Check Apache
    apache_avail = f'/etc/apache2/sites-available/{domain}.conf'
    if os.path.exists(apache_avail):
        try:
            cmd = ['a2ensite', f"{domain}.conf"] if enable else ['a2dissite', f"{domain}.conf"]
            subprocess.run(cmd, check=True, capture_output=True)
            subprocess.run(['systemctl', 'reload', 'apache2'], check=True)
            successes.append("Apache")
        except Exception as e:
            errors.append(f"Apache: {str(e)}")

    if errors:
        return False, f"Errors: {', '.join(errors)}"
    elif successes:
        return True, f"Domain {domain} {'enabled' if enable else 'disabled'} successfully on: {', '.join(successes)}."
    else:
        return False, "Configuration not found for any web server."

def delete_virtual_host(domain):
    """
    Deletes the virtual host configuration files, disables it, and removes the document root.
    """
    import shutil
    successes = []
    errors = []

    # Nginx
    nginx_avail = f'/etc/nginx/sites-available/{domain}'
    nginx_enabled = f'/etc/nginx/sites-enabled/{domain}'
    if os.path.exists(nginx_enabled):
        try:
            os.remove(nginx_enabled)
        except Exception as e:
            errors.append(f"Nginx disable: {str(e)}")
    if os.path.exists(nginx_avail):
        try:
            os.remove(nginx_avail)
            successes.append("Nginx config removed")
        except Exception as e:
            errors.append(f"Nginx config remove: {str(e)}")

    # Apache
    apache_avail = f'/etc/apache2/sites-available/{domain}.conf'
    apache_enabled = f'/etc/apache2/sites-enabled/{domain}.conf'
    if os.path.exists(apache_enabled):
        try:
            subprocess.run(['a2dissite', f"{domain}.conf"], check=False, capture_output=True)
        except Exception as e:
            errors.append(f"Apache disable: {str(e)}")
    if os.path.exists(apache_avail):
        try:
            os.remove(apache_avail)
            successes.append("Apache config removed")
        except Exception as e:
            errors.append(f"Apache config remove: {str(e)}")

    # Reload services if any configs were removed
    if successes:
        subprocess.run(['systemctl', 'reload', 'nginx'], check=False)
        subprocess.run(['systemctl', 'reload', 'apache2'], check=False)

    # Remove Document Root
    doc_root = f'/var/www/{domain}'
    if os.path.exists(doc_root):
        try:
            shutil.rmtree(doc_root)
            successes.append("Document root removed")
        except Exception as e:
            errors.append(f"Doc root remove: {str(e)}")

    if errors:
        return False, f"Deleted with errors: {', '.join(errors)}"
    elif successes:
        return True, f"Domain {domain} deleted successfully."
    else:
        return False, "Configuration not found to delete."


def get_port80_webserver(domain):
    """
    Checks the configuration files for a domain to see which webserver is serving port 80.
    Returns 'nginx', 'apache', or None.
    """
    # Check Nginx first (usually the frontend in hybrid stacks)
    nginx_conf = f'/etc/nginx/sites-available/{domain}'
    if os.path.exists(nginx_conf):
        try:
            with open(nginx_conf, 'r') as f:
                content = f.read()
                # Look for listen 80 or listen [::]:80
                if 'listen 80' in content or 'listen [::]:80' in content:
                    return 'nginx'
        except Exception:
            pass

    # Check Apache
    apache_conf = f'/etc/apache2/sites-available/{domain}.conf'
    if os.path.exists(apache_conf):
        try:
            with open(apache_conf, 'r') as f:
                content = f.read()
                # Look for <VirtualHost *:80>
                if '<VirtualHost *:80>' in content or '<VirtualHost _default_:80>' in content:
                    return 'apache'
        except Exception:
            pass

    return None
