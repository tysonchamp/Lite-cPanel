# 🚀 Lite-cPanel Git CI/CD & Auto-Deploy Guide

Lite-cPanel includes a built-in, Vercel-like Git CI/CD engine designed to automatically deploy your web applications and domains whenever you push commits to GitHub, GitLab, or any custom Git provider.

This guide covers:
- [Core Architecture & How It Works](#-how-it-works)
- [Repository Authentication (Public & Private)](#-repository-authentication)
- [Setting Up Webhooks (GitHub & GitLab)](#-setting-up-webhooks)
- [Deploying Next.js Applications](#1%EF%B8%8F%E2%83%A3-nextjs-applications)
- [Deploying Docker Applications](#2%EF%B8%8F%E2%83%A3-docker-applications)
- [Deploying PHP & Laravel Applications](#3%EF%B8%8F%E2%83%A3-php--laravel-applications)
- [Connecting Existing Production Folders](#-connecting-pre-existing-production-folders)
- [Troubleshooting & FAQs](#-troubleshooting--faqs)

---

## ⚙️ How It Works

```mermaid
flowchart LR
    A[Git Push to GitHub / GitLab] -->|Webhook POST /api/webhook/:token| B[Lite-cPanel CI/CD Engine]
    Manual[1-Click Deploy Button] --> B
    B --> C{Verify & Branch Check}
    C -->|Fetch & Hard Reset| D[Working Directory Sync]
    D --> E{App Type?}
    E -->|Next.js| F[Install & Build & PM2 Reload]
    E -->|Docker| G[docker compose up -d --build]
    E -->|PHP / Laravel| H[Composer & Post-Deploy Commands]
    F --> I[Live Deployment Logs & Status]
    G --> I
    H --> I
```

1. **Deterministic, Conflict-Free Sync**: Deployments use `git fetch` followed by `git checkout -f -B <branch> origin/<branch>` and `git reset --hard origin/<branch>`. This guarantees your server matches your remote branch without merge conflicts, while **preserving uncommitted server secrets (`.env`, `.env.production`) and uploaded media (`storage/`, `public/uploads/`)**.
2. **Push-to-Deploy**: Every connected repository receives a unique Webhook URL and HMAC-SHA256 Secret.
3. **Live Terminal Output**: Build steps stream output in real-time to a sleek dark terminal modal with 2-second auto-polling.
4. **1-Click Manual Deploy**: Quick-redeploy buttons are accessible right from the Domains, Next.js, and Docker dashboard tables.
5. **Automated FTP & Web Permissions Alignment**: Automatically detects the domain or FTP/SFTP user (e.g. `vaiska:vaiska` or `www-data:www-data`) and aligns all deployed and built files to `0660` / `0770` with `SetGID (g+s)`. This ensures both the FTP user and the web server (`www-data`) have full read/write access to all project files.

---

## 🔑 Repository Authentication

Lite-cPanel supports both public and private repositories.

### 1. Public Repositories
- **Authentication Method**: Select **Public Repo**.
- **URL**: Any standard HTTPS URL (e.g., `https://github.com/username/my-repo.git`).
- No tokens or SSH keys needed.

---

### 2. Private Repositories via SSH Deploy Key (Recommended)
Lite-cPanel generates a dedicated `ed25519` (or 4096-bit RSA) SSH keypair per repository.

1. In Lite-cPanel, select **SSH Deploy Key (Private - Recommended)**.
2. In the repository URL, enter either:
   - SSH format: `git@github.com:username/my-repo.git`
   - HTTPS format: `https://github.com/username/my-repo.git` *(Lite-cPanel automatically converts this to SSH)*
3. Click **Setup** (or open the repository settings) and click **Copy SSH Public Key**.
4. Add the public key to your Git provider:
   - **GitHub**: Go to `https://github.com/<owner>/<repo>/settings/keys` &rarr; Click **Add deploy key** &rarr; Paste key &rarr; Save (Read-only access is sufficient).
   - **GitLab**: Go to `Settings` &rarr; `Repository` &rarr; `Deploy keys` &rarr; Paste key &rarr; Save.

---

### 3. Private Repositories via Personal Access Token (PAT)
1. Generate a token on GitHub:
   - **GitHub**: `Settings` &rarr; `Developer Settings` &rarr; `Personal access tokens` &rarr; Generate token with `repo` (or fine-grained `Contents: Read`) permissions.
   - **GitLab**: `Preferences` &rarr; `Access Tokens` &rarr; `read_repository`.
2. In Lite-cPanel, select **Personal Access Token (HTTPS)**.
3. Paste the token into the token input box.
4. Lite-cPanel automatically handles authentication over HTTPS.

---

## 🪝 Setting Up Webhooks

To enable automatic deployment whenever you `git push`:

1. Open Lite-cPanel &rarr; **CI/CD** &rarr; Click **Setup** on your repository.
2. Copy the **Webhook Payload URL** (e.g. `http://<your-server-ip>:2087/api/webhook/<token>`).
3. Note or set your **Webhook Secret**.
4. Configure the webhook in GitHub or GitLab:

### GitHub:
1. Go to your repository &rarr; **Settings** &rarr; **Webhooks** &rarr; **Add webhook**.
2. **Payload URL**: Paste the Webhook URL from Lite-cPanel.
3. **Content type**: Select `application/json` *(Important!)*.
4. **Secret**: Paste your Webhook Secret (or leave blank if disabled in Lite-cPanel).
5. **Which events would you like to trigger this webhook?**: Choose **Just the push event**.
6. Click **Add webhook**.

### GitLab:
1. Go to your repository &rarr; **Settings** &rarr; **Webhooks** &rarr; **Add new webhook**.
2. **URL**: Paste the Webhook URL.
3. **Secret token**: Paste your Webhook Secret.
4. **Trigger**: Check **Push events** (specify your branch, e.g., `main`).
5. Click **Add webhook**.

---

## 1️⃣ Next.js Applications

Lite-cPanel provides full lifecycle management for Next.js applications, building production bundles and restarting PM2 with zero downtime.

### How Lite-cPanel Builds Next.js:
1. Detects your package manager automatically:
   - `pnpm-lock.yaml` &rarr; Uses `pnpm install`
   - `yarn.lock` &rarr; Uses `yarn install`
   - Default &rarr; Uses `npm install`
2. Runs the production build:
   - Default: `npm run build` (or `pnpm build` / `yarn build`)
   - Custom command: Runs whatever is specified in **Custom Build Command** (e.g., `npx prisma generate && npm run build`).
3. Reloads PM2:
   - Runs `pm2 reload <app_name>` (zero downtime graceful reload).
   - If reload fails (e.g. first run), falls back to `pm2 restart <app_name>`.
   - Runs `pm2 save` to keep process state across server reboots.

### Step-by-Step Setup:
1. Create or register your Next.js app in Lite-cPanel's **Next.js Manager** (e.g., domain `my-nextjs.com`, directory `/var/www/my-nextjs.com`, PM2 process `my-nextjs`).
2. Go to **Git CI/CD** &rarr; Click **Connect New Repository**.
3. In **Link To Existing Application / Domain**, select your Next.js app.
   - Lite-cPanel automatically fills in the target directory and PM2 process name.
4. Enter your Git Repository URL and Branch (`main`).
5. (Optional) Under **Advanced Build & PM2 Options**:
   - **Custom Build Command**: e.g., `npm run build` or `npx prisma generate && npm run build`
6. Click **Connect & Save**.

### Example `.env` Management for Next.js:
Keep your production secrets in `/var/www/my-nextjs.com/.env.production` or `.env.local`:
```bash
PORT=3000
NODE_ENV=production
DATABASE_URL="postgresql://user:password@localhost:5432/mydb"
NEXT_PUBLIC_API_URL="https://api.my-nextjs.com"
```
> [!NOTE]
> Git deployments will **never** overwrite or delete your `.env` files.

---

## 2️⃣ Docker Applications

Lite-cPanel allows you to manage multi-container applications with Docker Compose and redeploy them on Git push.

### How Lite-cPanel Builds Docker Apps:
1. Verifies `docker-compose.yml` or `docker-compose.yaml` exists in the target directory.
2. Executes:
   ```bash
   docker compose up -d --build
   ```
3. Automatically prunes dangling images to conserve server disk space:
   ```bash
   docker image prune -f
   ```

### Step-by-Step Setup:
1. Create a Docker domain in Lite-cPanel's **Docker Manager** (e.g., `/var/www/my-docker-app`).
2. Put your `docker-compose.yml` in `/var/www/my-docker-app/docker-compose.yml`.
3. In **Git CI/CD**, click **Connect New Repository**.
4. Select your Docker app from the dropdown (or specify `/var/www/my-docker-app`).
5. Choose **Docker Application (docker compose up -d --build)**.
6. Enter the Git URL and branch.
7. Click **Connect & Save**.

### Example `docker-compose.yml` (Next.js + PostgreSQL):
```yaml
version: '3.8'

services:
  web:
    build:
      context: .
      dockerfile: Dockerfile
    restart: always
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://dbuser:secret@db:5432/appdb
    depends_on:
      - db

  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_USER: dbuser
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: appdb
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

---

## 3️⃣ PHP & Laravel Applications

Lite-cPanel natively handles traditional PHP websites, WordPress, and modern PHP frameworks like **Laravel**, **Symfony**, and **CodeIgniter**.

### Default PHP Lifecycle:
1. **Composer Dependencies**: If `composer.json` is detected, Lite-cPanel runs:
   ```bash
   composer install --no-dev --optimize-autoloader --no-interaction
   ```
2. **File Permissions**: Automatically fixes permissions to prevent permission errors:
   ```bash
   chown -R www-data:www-data /var/www/<domain>
   ```
3. **OPCache Reload**: Automatically signals PHP-FPM (`php8.3-fpm`, `php8.2-fpm`, etc.) to reload and instantly invalidate cached bytecode without restarting the webserver.
4. **Post-Deploy Hook**: Runs your **Custom Post-Deploy Command** in the project directory.

---

### Step-by-Step Guide for Laravel

#### 1. Folder & Document Root Structure
In Laravel, public web traffic must be served from the `public/` directory, while your repository root contains `app/`, `artisan`, `composer.json`, and `.env`.

- In Lite-cPanel **Domain Manager**:
  - Add domain `restaurant-erp.com` with Document Root set to:
    ```text
    /var/www/restaurant-erp.com/public
    ```
- In Lite-cPanel **Git CI/CD**:
  - Set the **Target Directory** to the project root:
    ```text
    /var/www/restaurant-erp.com
    ```

#### 2. Configuring Post-Deploy Commands for Laravel
In Lite-cPanel CI/CD, you can specify a **Custom Post-Deploy Command**. This runs inside the target directory immediately after the code is updated and composer packages are installed.

#### Common Laravel Deployment Commands:

##### A. Complete Standard Production Pipeline (Recommended)
```bash
php artisan migrate --force && php artisan optimize:clear && php artisan optimize && php artisan view:cache
```

##### B. Detailed Breakdown of Commands:

| Command | Purpose |
| :--- | :--- |
| `composer install --no-dev --optimize-autoloader` | Installs production PHP dependencies *(runs automatically if `composer.json` exists)* |
| `composer update --no-dev --optimize-autoloader` | Updates dependencies according to `composer.json` versions *(use with care in production)* |
| `php artisan migrate --force` | Runs new database schema migrations without interactive confirmation prompts |
| `php artisan db:seed --force` | (Optional) Seeds database tables |
| `php artisan storage:link` | Generates the public symbolic link for uploaded files (`public/storage` &rarr; `storage/app/public`) |
| `php artisan config:cache` | Caches `.env` configuration into a single fast-loading file |
| `php artisan route:cache` | Pre-compiles all Laravel routes into high-performance metadata |
| `php artisan view:cache` | Compiles all Blade templates into raw PHP |
| `php artisan optimize:clear` | Clears all existing configuration, route, and compiled caches |
| `php artisan optimize` | Re-compiles configuration and routes together |
| `php artisan queue:restart` | Gracefully reloads background queue workers (Horizon or Supervisor) to run latest code |

##### C. Recommended Laravel Post-Deploy String:
Paste this into the **Custom Post-Deploy Command** field in Lite-cPanel:
```bash
php artisan storage:link; php artisan migrate --force && php artisan optimize:clear && php artisan optimize && php artisan queue:restart
```

#### 3. Laravel `.env` Configuration
On your server, create `/var/www/restaurant-erp.com/.env`:
```ini
APP_NAME=RestaurantERP
APP_ENV=production
APP_KEY=base64:...
APP_DEBUG=false
APP_URL=https://restaurant-erp.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=restaurant_db
DB_USERNAME=restaurant_user
DB_PASSWORD=your_strong_password
```
> [!IMPORTANT]
> The server's `.env` file is untracked by Git and will remain intact across all future deployments.

---

## 📂 Connecting Pre-Existing Production Folders

If you already have files on your production server (e.g. uploaded via FTP/ZIP) and want to attach Git without losing local data:

1. In Lite-cPanel, go to **Git CI/CD** &rarr; **Connect Git Repository**.
2. Enter the path of your existing folder (e.g. `/var/www/restaurant-erp.com`).
3. Enter your Git repository URL and branch.
4. Lite-cPanel will:
   - Initialize Git in the existing folder if needed.
   - Fetch the latest commits from your remote.
   - Force-checkout and hard-reset the tracked files to match the remote branch.
   - **Preserve all server-specific untracked files** (such as `.env`, `.env.local`, uploaded media in `public/uploads/` or `storage/`).

---

## 🛠️ Troubleshooting & FAQs

### 1. `fatal: detected dubious ownership in repository at '/var/www/...'`
- **Cause**: Git 2.35.2+ security check triggers when the executing user (`root`) differs from the directory owner (`www-data`).
- **Solution**: Lite-cPanel automatically passes `-c safe.directory=*` on all commands and configures global safe directories. To apply manually on server:
  ```bash
  git config --global --add safe.directory '*'
  ```

### 2. `error: The following untracked working tree files would be overwritten by merge`
- **Cause**: Standard `git pull` attempts a merge and aborts if untracked files match repository files.
- **Solution**: Lite-cPanel CI/CD uses `git checkout -f -B <branch> origin/<branch>` followed by `git reset --hard origin/<branch>`, which adopts the files without merge conflicts.

### 3. `fatal: Could not read from remote repository / Please make sure you have the correct access rights`
- **Cause**: Attempting to fetch a private repository without credentials.
- **Solution**: Click **Setup** in Lite-cPanel &rarr; Select **SSH Deploy Key** &rarr; Copy the public key and add it to GitHub under **Repo Settings &rarr; Deploy keys**.

### 4. `Signature verification failed: GitHub signature mismatch`
- **Cause**: The Webhook Secret in GitHub doesn't match the secret saved in Lite-cPanel.
- **Solution**: In Lite-cPanel CI/CD, click **Setup** &rarr; Paste the same Secret you configured in GitHub (or leave blank in both to disable verification) &rarr; Click **Save Repository Settings**.

### 5. Where are deployment logs saved?
- Logs are displayed live in the web dashboard terminal modal.
- Raw logs are stored on disk at:
  ```text
  /etc/cpanel/cicd/logs/deploy_<repo_id>.log
  ```
