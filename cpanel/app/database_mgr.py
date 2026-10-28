import pymysql
import os
import secrets
import subprocess


SYSTEM_USERS = (
    'root',
    'mysql',
    'mariadb.sys',
    'mysql.sys',
    'mysql.session',
    'mysql.infoschema',
    'debian-sys-maint',
    'admin',
    'phpmyadmin'
)

def get_mysql_connection():
    """
    Attempts to connect to MySQL as root.
    It checks common locations for the root password created by the stack installer.
    """
    password = ''
    pass_file = '/var/lib/lite-cpanel/.passwords'
    if os.path.exists(pass_file):
        with open(pass_file, 'r') as f:
            for line in f:
                if line.startswith('MySQL Root Password:'):
                    password = line.split(':', 1)[1].strip()
                    break
            
    sock_paths = ['/var/run/mysqld/mysqld.sock', '/tmp/mysql.sock']
    sock = None
    for s in sock_paths:
        if os.path.exists(s):
            sock = s
            break

    try:
        if sock:
            connection = pymysql.connect(
                unix_socket=sock,
                user='root',
                password=password,
                cursorclass=pymysql.cursors.DictCursor
            )
        else:
            connection = pymysql.connect(
                host='localhost',
                user='root',
                password=password,
                cursorclass=pymysql.cursors.DictCursor
            )
        return connection
    except pymysql.MySQLError as e:
        # Maybe passwordless root login is enabled via unix_socket
        try:
            if sock:
                connection = pymysql.connect(
                    unix_socket=sock,
                    user='root',
                    cursorclass=pymysql.cursors.DictCursor
                )
            else:
                connection = pymysql.connect(
                    host='localhost',
                    user='root',
                    cursorclass=pymysql.cursors.DictCursor
                )
            return connection
        except pymysql.MySQLError as e2:
            return None

def get_databases():
    """Returns a list of user databases (excluding system DBs)."""
    conn = get_mysql_connection()
    if not conn: return []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SHOW DATABASES")
            dbs = cursor.fetchall()
            return [db['Database'] for db in dbs if db['Database'] not in ('information_schema', 'mysql', 'performance_schema', 'sys')]
    finally:
        conn.close()

def get_database_details():
    """
    Returns a list of dicts with db name, plus all users and their allowed hosts and
    permissions (readonly vs readwrite) that have privileges on each database.
    """
    conn = get_mysql_connection()
    if not conn: return []
    try:
        with conn.cursor() as cursor:
            cursor.execute("SHOW DATABASES")
            raw_dbs = [db['Database'] for db in cursor.fetchall()
                       if db['Database'] not in ('information_schema', 'mysql', 'performance_schema', 'sys')]

            result = []
            for db in raw_dbs:
                cursor.execute(
                    "SELECT User, Host, Select_priv, Insert_priv, Update_priv, Delete_priv, "
                    "Create_priv, Drop_priv, Alter_priv "
                    "FROM mysql.db WHERE Db = %s ORDER BY User, Host",
                    (db,)
                )
                raw_users = cursor.fetchall()
                users = []
                for u in raw_users:
                    if u['User'].lower() in [s.lower() for s in SYSTEM_USERS]:
                        continue
                    # Check if user is read-only (SELECT granted, no write/modify privileges)
                    is_ro = (
                        u.get('Select_priv') == 'Y' and
                        u.get('Insert_priv') == 'N' and
                        u.get('Update_priv') == 'N' and
                        u.get('Delete_priv') == 'N' and
                        u.get('Create_priv') == 'N' and
                        u.get('Drop_priv') == 'N' and
                        u.get('Alter_priv') == 'N'
                    )
                    users.append({
                        'User': u['User'],
                        'Host': u['Host'],
                        'permission': 'readonly' if is_ro else 'readwrite',
                        'permission_label': 'Read Only' if is_ro else 'Read & Write'
                    })
                result.append({'name': db, 'users': users})
            return result
    finally:
        conn.close()

def change_user_password(db_user, host, new_password):
    conn = get_mysql_connection()
    if not conn: return False, "Could not connect to database server."
    try:
        with conn.cursor() as cursor:
            # Use %s parameterized query for the password — pymysql handles all escaping safely.
            # Manually single-quote-escape user and host (identifiers, not values).
            user_esc = db_user.replace("'", "''")
            host_esc = host.replace("'", "''")
            cursor.execute(
                f"ALTER USER '{user_esc}'@'{host_esc}' IDENTIFIED BY %s",
                (new_password,)
            )
            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        return True, f"Password updated for {db_user}@{host}."
    except pymysql.MySQLError as e:
        return False, f"Error: {str(e)}"
    finally:
        conn.close()

def update_user_host(db_name, db_user, old_host, new_host):
    """
    Changes a user's host, effectively toggling between 'localhost' (local-only)
    and '%' (remote access allowed).
    """
    conn = get_mysql_connection()
    if not conn: return False, "Could not connect to database server."
    try:
        with conn.cursor() as cursor:
            db_escaped  = db_name.replace('`', '``')
            new_host_esc = pymysql.converters.escape_string(new_host)
            old_host_esc = pymysql.converters.escape_string(old_host)
            user_esc     = pymysql.converters.escape_string(db_user)

            # Rename the user
            cursor.execute(
                f"RENAME USER '{user_esc}'@'{old_host_esc}' TO '{user_esc}'@'{new_host_esc}'"
            )
            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        label = 'remote (%)' if new_host == '%' else 'local (localhost)'
        return True, f"{db_user} host updated to {label}."
    except pymysql.MySQLError as e:
        return False, f"Error: {str(e)}"
    finally:
        conn.close()

def create_database(db_name, db_user, db_pass):
    conn = get_mysql_connection()
    if not conn: return False, "Could not connect to database server."

    try:
        with conn.cursor() as cursor:
            # Escape identifiers (db_name, db_user) by quoting backticks.
            # Use %s parameterized query for the password.
            db_name_esc = db_name.replace('`', '``')
            db_user_esc = db_user.replace('`', '``')
            user_host   = db_user.replace("'", "''")

            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name_esc}`")
            cursor.execute(
                f"CREATE USER IF NOT EXISTS '{user_host}'@'localhost' IDENTIFIED BY %s",
                (db_pass,)
            )
            # Force update the password in case the user already existed
            cursor.execute(
                f"ALTER USER '{user_host}'@'localhost' IDENTIFIED BY %s",
                (db_pass,)
            )
            cursor.execute(f"GRANT ALL PRIVILEGES ON `{db_name_esc}`.* TO '{user_host}'@'localhost'")
            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        return True, "Database and user created successfully."
    except pymysql.MySQLError as e:
        return False, f"Database error: {str(e)}"
    finally:
        if conn:
            conn.close()

def delete_database(db_name):
    conn = get_mysql_connection()
    if not conn: return False, "Could not connect to database server."

    dropped_users = []
    try:
        with conn.cursor() as cursor:
            # Find all users that have privileges on this specific database
            cursor.execute(
                "SELECT User, Host FROM mysql.db WHERE Db = %s",
                (db_name,)
            )
            affected_users = cursor.fetchall()  # [{User: ..., Host: ...}, ...]

            for u in affected_users:
                user_esc = u['User'].replace("'", "''")
                host_esc = u['Host'].replace("'", "''")

                # Check if this user has grants on ANY other database
                cursor.execute(
                    "SELECT COUNT(*) as cnt FROM mysql.db WHERE User = %s AND Host = %s AND Db != %s",
                    (u['User'], u['Host'], db_name)
                )
                row = cursor.fetchone()
                other_db_count = row['cnt'] if row else 0

                if other_db_count == 0:
                    # User is exclusive to this DB — safe to fully drop them
                    cursor.execute(f"DROP USER IF EXISTS '{user_esc}'@'{host_esc}'")
                    dropped_users.append(f"{u['User']}@{u['Host']}")
                else:
                    # User has other databases — only revoke privileges on this DB
                    db_esc = db_name.replace('`', '``')
                    cursor.execute(
                        f"REVOKE ALL PRIVILEGES ON `{db_esc}`.* FROM '{user_esc}'@'{host_esc}'"
                    )

            db_esc = db_name.replace('`', '``')
            cursor.execute(f"DROP DATABASE IF EXISTS `{db_esc}`")
            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()

        msg = "Database deleted successfully."
        if dropped_users:
            msg += f" Removed users: {', '.join(dropped_users)}."
        return True, msg
    except pymysql.MySQLError as e:
        return False, f"Database error: {str(e)}"
    finally:
        if conn:
            conn.close()

def setup_phpmyadmin_signon():
    """
    Cleans up any previous phpMyAdmin signon configuration to allow manual login.
    """
    try:
        # Cleanup SSO config file
        sso_config = '/etc/phpmyadmin/conf.d/cpanel_signon.php'
        if os.path.exists(sso_config):
            os.remove(sso_config)
        
        # Cleanup basedir override
        basedir_conf = '/etc/apache2/conf-available/cpanel-pma-basedir.conf'
        if os.path.exists(basedir_conf):
            import subprocess as _sp
            _sp.run(['a2disconf', 'cpanel-pma-basedir'], capture_output=True)
            os.remove(basedir_conf)
            _sp.run(['systemctl', 'reload', 'apache2'], capture_output=True)
            
        # Cleanup login script
        login_script = '/usr/share/phpmyadmin/phpmyadmin_login.php'
        if os.path.exists(login_script):
            os.remove(login_script)
            
        # Cleanup token directory
        import shutil
        token_dir = '/var/lib/cpanel_tokens'
        if os.path.exists(token_dir):
            shutil.rmtree(token_dir)
            
        return True, "Signon features removed."
    except Exception as e:
        return False, f"Error during cleanup: {str(e)}"

def get_all_mysql_users():
    """
    Returns a list of distinct user accounts (excluding system accounts)
    for easy selection when attaching users.
    """
    conn = get_mysql_connection()
    if not conn: return []
    try:
        with conn.cursor() as cursor:
            placeholders = ', '.join(['%s'] * len(SYSTEM_USERS))
            cursor.execute(
                f"SELECT DISTINCT User FROM mysql.user WHERE LOWER(User) NOT IN ({placeholders}) ORDER BY User",
                [s.lower() for s in SYSTEM_USERS]
            )
            return [row['User'] for row in cursor.fetchall()]
    except Exception:
        return []
    finally:
        if conn:
            conn.close()

def attach_user_to_db(db_name, db_user, host='localhost', password=None, permission='readonly'):
    """
    Attaches a user to a database with specified permission ('readonly' or 'readwrite').
    If the user does not exist in MySQL, creates the user with the given password.
    If the user exists, optionally updates their password if provided.
    """
    if db_user.lower() in [s.lower() for s in SYSTEM_USERS]:
        return False, f"Protected system account '{db_user}' cannot be modified."

    if permission not in ('readonly', 'readwrite'):
        return False, "Invalid permission level. Must be 'readonly' or 'readwrite'."

    conn = get_mysql_connection()
    if not conn: return False, "Could not connect to database server."

    try:
        with conn.cursor() as cursor:
            db_name_esc = db_name.replace('`', '``')
            user_esc = db_user.replace("'", "''")
            host_esc = host.replace("'", "''")

            # Check if user already exists
            cursor.execute("SELECT User, Host FROM mysql.user WHERE User = %s AND Host = %s", (db_user, host))
            user_exists = cursor.fetchone() is not None

            if not user_exists:
                if not password:
                    return False, f"Password is required to create new user '{db_user}'@'{host}'."
                cursor.execute(
                    f"CREATE USER '{user_esc}'@'{host_esc}' IDENTIFIED BY %s",
                    (password,)
                )
            else:
                if password:
                    cursor.execute(
                        f"ALTER USER '{user_esc}'@'{host_esc}' IDENTIFIED BY %s",
                        (password,)
                    )

            if permission == 'readonly':
                try:
                    cursor.execute(f"REVOKE ALL PRIVILEGES ON `{db_name_esc}`.* FROM '{user_esc}'@'{host_esc}'")
                except pymysql.MySQLError:
                    pass
                cursor.execute(f"GRANT SELECT, SHOW VIEW ON `{db_name_esc}`.* TO '{user_esc}'@'{host_esc}'")
            else:
                cursor.execute(f"GRANT ALL PRIVILEGES ON `{db_name_esc}`.* TO '{user_esc}'@'{host_esc}'")

            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        perm_label = "Read Only" if permission == 'readonly' else "Read & Write"
        return True, f"User '{db_user}'@'{host}' successfully attached to '{db_name}' with {perm_label} permissions."
    except pymysql.MySQLError as e:
        return False, f"Database error: {str(e)}"
    finally:
        if conn:
            conn.close()

def set_user_permissions(db_name, db_user, host, permission='readonly'):
    """
    Updates the permissions of an existing user on a database to 'readonly' or 'readwrite'.
    """
    if db_user.lower() in [s.lower() for s in SYSTEM_USERS]:
        return False, f"Protected system account '{db_user}' cannot be modified."

    if permission not in ('readonly', 'readwrite'):
        return False, "Invalid permission level. Must be 'readonly' or 'readwrite'."

    conn = get_mysql_connection()
    if not conn: return False, "Could not connect to database server."

    try:
        with conn.cursor() as cursor:
            db_name_esc = db_name.replace('`', '``')
            user_esc = db_user.replace("'", "''")
            host_esc = host.replace("'", "''")

            if permission == 'readonly':
                try:
                    cursor.execute(f"REVOKE ALL PRIVILEGES ON `{db_name_esc}`.* FROM '{user_esc}'@'{host_esc}'")
                except pymysql.MySQLError:
                    pass
                cursor.execute(f"GRANT SELECT, SHOW VIEW ON `{db_name_esc}`.* TO '{user_esc}'@'{host_esc}'")
            else:
                cursor.execute(f"GRANT ALL PRIVILEGES ON `{db_name_esc}`.* TO '{user_esc}'@'{host_esc}'")

            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        perm_label = "Read Only" if permission == 'readonly' else "Read & Write (All Privileges)"
        return True, f"Permissions for '{db_user}'@'{host}' on '{db_name}' updated to {perm_label}."
    except pymysql.MySQLError as e:
        return False, f"Database error: {str(e)}"
    finally:
        if conn:
            conn.close()

def detach_user_from_db(db_name, db_user, host, delete_user=False):
    """
    Detaches a user from a database by revoking all privileges on it.
    If delete_user is True, also permanently deletes the user account from MySQL.
    """
    if db_user.lower() in [s.lower() for s in SYSTEM_USERS]:
        return False, f"Protected system account '{db_user}' cannot be detached."

    conn = get_mysql_connection()
    if not conn: return False, "Could not connect to database server."

    try:
        with conn.cursor() as cursor:
            db_name_esc = db_name.replace('`', '``')
            user_esc = db_user.replace("'", "''")
            host_esc = host.replace("'", "''")

            # Revoke privileges on this DB
            try:
                cursor.execute(f"REVOKE ALL PRIVILEGES ON `{db_name_esc}`.* FROM '{user_esc}'@'{host_esc}'")
            except pymysql.MySQLError:
                pass

            msg = f"User '{db_user}'@'{host}' detached from '{db_name}'."
            if delete_user:
                cursor.execute(f"DROP USER IF EXISTS '{user_esc}'@'{host_esc}'")
                msg += f" (User '{db_user}'@'{host}' permanently deleted from MySQL)."

            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        return True, msg
    except pymysql.MySQLError as e:
        return False, f"Database error: {str(e)}"
    finally:
        if conn:
            conn.close()

def delete_mysql_user(db_user, host):
    """
    Permanently deletes a MySQL user account and all their database privileges.
    """
    if db_user.lower() in [s.lower() for s in SYSTEM_USERS]:
        return False, f"Protected system account '{db_user}' cannot be deleted."

    conn = get_mysql_connection()
    if not conn: return False, "Could not connect to database server."

    try:
        with conn.cursor() as cursor:
            user_esc = db_user.replace("'", "''")
            host_esc = host.replace("'", "''")

            cursor.execute(f"DROP USER IF EXISTS '{user_esc}'@'{host_esc}'")
            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        return True, f"User '{db_user}'@'{host}' permanently deleted from MySQL."
    except pymysql.MySQLError as e:
        return False, f"Database error: {str(e)}"
    finally:
        if conn:
            conn.close()

def get_all_users_details():
    """
    Returns a list of all non-system MySQL users, their host, and the list of
    databases they currently have privileges on.
    """
    conn = get_mysql_connection()
    if not conn: return []
    try:
        with conn.cursor() as cursor:
            placeholders = ', '.join(['%s'] * len(SYSTEM_USERS))
            cursor.execute(
                f"SELECT User, Host FROM mysql.user WHERE LOWER(User) NOT IN ({placeholders}) ORDER BY User, Host",
                [s.lower() for s in SYSTEM_USERS]
            )
            raw_users = cursor.fetchall()
            
            users = []
            for u in raw_users:
                cursor.execute(
                    "SELECT Db, Select_priv, Insert_priv, Update_priv, Delete_priv, "
                    "Create_priv, Drop_priv, Alter_priv FROM mysql.db WHERE User = %s AND Host = %s ORDER BY Db",
                    (u['User'], u['Host'])
                )
                db_grants = cursor.fetchall()
                dbs = []
                for g in db_grants:
                    is_ro = (
                        g.get('Select_priv') == 'Y' and
                        g.get('Insert_priv') == 'N' and
                        g.get('Update_priv') == 'N' and
                        g.get('Delete_priv') == 'N' and
                        g.get('Create_priv') == 'N' and
                        g.get('Drop_priv') == 'N' and
                        g.get('Alter_priv') == 'N'
                    )
                    dbs.append({
                        'db_name': g['Db'],
                        'permission': 'readonly' if is_ro else 'readwrite',
                        'permission_label': 'Read Only' if is_ro else 'Read & Write'
                    })
                
                users.append({
                    'User': u['User'],
                    'Host': u['Host'],
                    'databases': dbs,
                    'is_unassigned': len(dbs) == 0
                })
            return users
    except Exception:
        return []
    finally:
        if conn:
            conn.close()

