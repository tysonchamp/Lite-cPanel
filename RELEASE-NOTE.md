# Updates:

## 28.10.2026 (Git CI/CD & Automated Continuous Deployment)

1. **Continuous Deployment (Vercel-like)**: Added automated Git push-to-deploy webhooks supporting GitHub, GitLab, and custom Git providers for Next.js apps, Docker containers, and traditional PHP/HTML domains.
2. **Public & Private Repository Support**: Built-in automated ed25519 SSH Deploy Key generation with 1-click copy buttons for GitHub/GitLab Deploy Keys, alongside Personal Access Token (PAT) authentication for HTTPS private repos.
3. **Application Lifecycle Handlers**:
   - **Next.js**: Auto-detects package managers (`npm`, `pnpm`, `yarn`), installs dependencies, runs production build (`npm run build`), and performs zero-downtime reloads in PM2 (`pm2 reload`).
   - **Docker**: Runs `docker compose up -d --build` with automatic dangling image cleanup (`docker image prune -f`).
   - **Domains (PHP / HTML)**: Pulls latest code, runs `composer install` (if `composer.json` is present), enforces secure `www-data:www-data` ownership, and reloads PHP-FPM to clear bytecode OPCaches.
4. **Secure Webhook Endpoint**: Added `/api/webhook/<token>` with cryptographic HMAC-SHA256 signature verification (`X-Hub-Signature-256` for GitHub, `X-Gitlab-Token` for GitLab), branch filtering, and non-blocking background queue execution.
5. **Live Log Viewer**: Terminal-styled log streaming modal in the UI with automatic 2-second polling to observe real-time build progress and commit metadata.
6. **Unified & Inline Controls**: Dedicated **Git CI/CD** dashboard in the sidebar, plus inline 1-click "Git Pull / Redeploy" action buttons directly in Domains, Next.js Apps, and Docker management tables.

## 08.7.2026 (Docker Container Manager)

1. **Docker Container Management**: Added a new dedicated Docker UI to seamlessly list, start, stop, restart, remove, and run containers with custom configurations directly from the panel.
2. **Docker Domain Proxying**: Implemented the ability to map domain names to internal Docker container ports using automated Nginx and Apache reverse proxy configurations.
3. **Automated Document Roots**: Creating a Docker proxy now automatically provisions a document root (`/var/www/{domain}`) for users to upload and manage configuration files.
4. **Docker Compose Integration**: Added a one-click "Build & Run" feature that detects a `docker-compose.yml` in the document root and executes a background build, automatically piping logs to `/var/log/docker_compose_{domain}.log`.
5. **Domain Manager Bug Fix**: Fixed an issue in `domains_mgr.py` where Docker Proxy apps were not being correctly filtered out of the standard Domain list due to a file reading bug.

## 06.07.2026 (pm2 bug fixes and Redis DB Management)

1. **PM2 Resurrection**: Added support for automatic PM2 resurrection on system boot to ensure Node.js applications persist across system restarts.
2. **Redis DB Management**: Added support for Redis DB Management.
3. **Redis Commander**: Added support for Redis Commander.

## 23.04.2026 (Security & Framework Optimization Update)

1. **Jailed SFTP (Chroot)**: Implemented ChrootDirectory for FTP users, restricting them to their home directories and enhancing server security.
2. **Private Group Isolation**: Refactored FTP user management to assign unique private groups to each user, ensuring total data privacy and preventing cross-account access.
3. **Global Security Shield**: Added an automated "Security Hardening" feature. This blocks access to all dotfiles (including `.env`) via web requests and disables directory indexing (Autoindex) on both Apache and Nginx.
4. **Framework Permission Fixes**: Enhanced the File Manager to automatically apply secure 770/660 permissions to web roots and specific framework directories (e.g., `/storage`, `/bootstrap/cache` for Laravel), resolving "Permission denied" errors.
5. **Performance & Reliability**:
   - Integrated a background caching worker for the Dashboard to pre-fetch system metrics, reducing load time by up to 90%.
   - Added automatic service restarts (Apache/Nginx/PHP-FPM) triggered by permission changes to ensure changes take effect immediately.
   - Fixed "Connection reset by peer" errors in SFTP by resolving path resolution logic.

## 21.04.2026 (Major UI & Analytics Update)

1. **Slick Modern UI/UX**: Completely redesigned the dashboard and sidebar with a premium midnight-gradient aesthetic, refined typography (Inter), and glassmorphism-inspired cards.
2. **Web Traffic Analytics**: Integrated **GoAccess** for real-time web traffic monitoring. Added a dedicated Traffic Monitor module providing per-domain hits, unique visitors, bandwidth stats, and full interactive HTML reports.
3. **Process Manager Hardening**: Implemented **Automatic PM2 Resurrection** on system boot and hardened NVM environment paths to ensure Node.js/Next.js applications persist across system restarts.
4. **Advanced System Metrics**: Expanded the server information module to display CPU clock frequency, platform details (Architecture/KVM), and full OS Distro names (e.g., AlmaLinux/Ubuntu).
5. **Security Log Parsing**: Enhanced SSH login audit logs with dual-format timestamp parsing (ISO/Syslog) for clean, human-readable security event monitoring.
6. **Terminal UX**: Upgraded the web terminal with a custom minimalist scrollbar and improved container styling for a pro-developer feel.
7. **Infrastructure Refactoring**: Migrated to a centralized `base.html` architecture to improve panel stability and eliminate template-related Internal Server Errors.

## 21.04.2026 (Initial Release)

1. Implemented a full **Node.js Process Manager** powered by PM2, allowing live monitoring and control of background applications.
2. Updated **Certbot** installation to the official Snap-based method for improved reliability on Ubuntu 22.04 and 24.04.
3. Enhanced **SSL Generation** with smart webserver detection (Apache vs Nginx) and automated DNS verification for subdomains to prevent NXDOMAIN failures.
4. Improved **System Health** dashboard with a persistent log viewer in Settings that ensures core log tabs are always accessible.
5. Added NVM path auto-detection to ensure `npm` and `node` are always available to the panel even when installed via version managers.
6. Established strict **Project Guidelines** to ensure production-ready standards for future developments.


## 13.04.2026

1. Script has been updated to 3.0. Major changes has been done to support latest Ubuntu LTS versions and latest webmin versions. Also added support for installing certbot for ssl certificates.
2. Added support for interactive menu to choose options during installation.
3. Improved error handling and logging for better troubleshooting.
4. Auto Installation of MariaDB & phpMyAdmin.
5. updated readme and documentation for better clarity.
6. Added multiple stack options including NGINX and hybrid configurations.
7. Added support for installing CSF firewall.
8. Added support for installing ModSecurity firewall.
9. Added support for installing Fail2Ban.
10. Added support for installing UFW firewall.
11. Added support for installing Nginx.
12. Added support for installing PHP.
13. Added support for installing MariaDB.
14. Added support for installing phpMyAdmin.
15. Added support for installing Certbot.
16. Added support for installing Webmin.
17. Added support for installing FTP.
18. Added support for installing SSH.

## 24.01.2016

1. Script has been updated to 1.0 with some new changes. Now users will have choice on installing webmin control panel and ssl certificates. Also http and https apache file config has been splited into two files for better management.

## 27.01.2016

1. Script has been updated to 1.1. Some minor changes has been done and permission checking has been added.

## 13.11.2025

1. Script has been updated to 2.0. Major changes has been done to support latest Ubuntu LTS versions and latest webmin versions. Also added support for installing certbot for ssl certificates.
2. Added support for interactive menu to choose options during installation.
3. Improved error handling and logging for better troubleshooting.
4. Auto Installation of MariaDB & phpMyAdmin.
5. updated readme and documentation for better clarity.
6. Added multiple stack options including NGINX and hybrid configurations.
