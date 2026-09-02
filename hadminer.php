<?php
session_start();

define('APP_NAME', 'HADminer');
define('ROWS_PER_PAGE', 25);
define('QUERY_HISTORY_MAX', 20);

// ── HASH DETECTION ────────────────────────────────────────────────────────────

function detectHashType(string $v): ?string {
    $v   = trim($v);
    $len = strlen($v);
    if ($len < 8) return null;

    // Prefixed / structured formats (most specific first)
    if (preg_match('/^\$2[ayb]\$\d{2}\$.{53}$/', $v))                           return 'bcrypt';
    if (str_starts_with($v, '$argon2'))                                           return 'Argon2';
    if (str_starts_with($v, '$6$'))                                               return 'sha512crypt';
    if (str_starts_with($v, '$5$'))                                               return 'sha256crypt';
    if (str_starts_with($v, '$1$') || str_starts_with($v, '$apr1$'))             return 'MD5crypt';
    if (str_starts_with($v, '$P$') || str_starts_with($v, '$H$'))                return 'WordPress/phpBB';
    if (str_starts_with($v, '$S$'))                                               return 'Drupal';
    if (str_starts_with($v, 'pbkdf2_sha'))                                        return 'Django PBKDF2';
    if (preg_match('/^pbkdf2:[^:]+:\d+:\d+:[a-f0-9]+$/i', $v))                  return 'Werkzeug PBKDF2';
    if (str_starts_with($v, '{SHA}'))                                             return 'SHA-1 (LDAP)';
    if (str_starts_with($v, '{SSHA}'))                                            return 'SSHA (LDAP)';
    if ($len === 41 && $v[0] === '*' && ctype_xdigit(substr($v, 1)))             return 'MySQL SHA-1';
    if (preg_match('/^sha1\$[a-z0-9]+\$[a-f0-9]{40}$/i', $v))                   return 'Django SHA-1';
    if (preg_match('/^md5\$[a-z0-9]+\$[a-f0-9]{32}$/i', $v))                    return 'Django MD5';
    if (preg_match('/^scrypt:[^:]+:[a-f0-9]+:[a-f0-9]+$/i', $v))                return 'scrypt';

    // Pure hex formats
    if (ctype_xdigit($v)) {
        return match($len) {
            16  => 'MySQL v3',
            32  => 'MD5 / NTLM',
            40  => 'SHA-1',
            56  => 'SHA-224',
            64  => 'SHA-256',
            96  => 'SHA-384',
            128 => 'SHA-512',
            default => null,
        };
    }

    // Base64-encoded hashes
    if (preg_match('/^[a-zA-Z0-9+\/]+=*$/', $v) && $len % 4 === 0) {
        $decoded = base64_decode($v, true);
        if ($decoded !== false) {
            return match(strlen($decoded)) {
                16 => 'MD5 (base64)',
                20 => 'SHA-1 (base64)',
                32 => 'SHA-256 (base64)',
                64 => 'SHA-512 (base64)',
                default => null,
            };
        }
    }

    return null;
}

// Returns CSS class for the hash strength indicator
function hashStrength(string $type): string {
    $weak   = ['MySQL v3','MD5 / NTLM','MD5 (base64)','MD5crypt','SHA-1','SHA-1 (LDAP)','SHA-1 (base64)','MySQL SHA-1','Django SHA-1','Django MD5'];
    $medium = ['SHA-224','SHA-256','SHA-256 (base64)','sha256crypt','SHA-384','WordPress/phpBB','Werkzeug PBKDF2','SSHA (LDAP)'];
    if (in_array($type, $weak))   return 'hw';  // weak   → red
    if (in_array($type, $medium)) return 'hm';  // medium → orange
    return 'hs';                                 // strong → green
}

function analyzeColumnHashes(string $colName, array $values): ?string {
    $hints    = ['password','passwd','pwd','hash','pass','token','secret','mdp','crypt','hashed','pw'];
    $colLower = strtolower($colName);
    $nameHit  = false;
    foreach ($hints as $h) { if (str_contains($colLower, $h)) { $nameHit = true; break; } }

    $found  = [];
    $nonNull = 0;
    foreach ($values as $v) {
        if ($v === null || $v === '') continue;
        $t = detectHashType((string)$v);
        if ($t) $found[$t] = ($found[$t] ?? 0) + 1;
        if (++$nonNull >= 10) break;
    }

    if (empty($found)) return null;
    arsort($found);
    $top = array_key_first($found);
    if ($nameHit || ($found[$top] / max($nonNull, 1)) >= 0.5) return $top;
    return null;
}

// ── DB ABSTRACTION ────────────────────────────────────────────────────────────

function makePdo(string $driver, string $host, int $port, string $user, string $pass, string $db = ''): PDO {
    $opts = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    $dsn = match($driver) {
        'mysql'  => "mysql:host={$host};port={$port}" . ($db ? ";dbname={$db}" : '') . ";charset=utf8mb4",
        'pgsql'  => "pgsql:host={$host};port={$port}" . ($db ? ";dbname={$db}" : ''),
        'sqlite' => "sqlite:{$host}",
        default  => throw new PDOException("Unknown driver: {$driver}"),
    };
    $u = ($driver === 'sqlite') ? null : $user;
    $p = ($driver === 'sqlite') ? null : $pass;
    return new PDO($dsn, $u, $p, $opts);
}

function autoDetect(string $host, int $port, string $user, string $pass): array {
    // SQLite: path-like host
    if (str_starts_with($host, '/') || preg_match('/\.(db|sqlite3?)$/i', $host)) {
        try { return ['driver' => 'sqlite', 'pdo' => makePdo('sqlite', $host, 0, '', '')]; }
        catch (PDOException) {}
    }
    foreach (['mysql', 'pgsql'] as $drv) {
        try { return ['driver' => $drv, 'pdo' => makePdo($drv, $host, $port, $user, $pass)]; }
        catch (PDOException) {}
    }
    throw new PDOException("Could not connect with any driver (mysql, pgsql, sqlite).");
}

function dbDatabases(PDO $pdo, string $drv): array {
    return match($drv) {
        'mysql'  => $pdo->query("SHOW DATABASES")->fetchAll(PDO::FETCH_COLUMN),
        'pgsql'  => $pdo->query("SELECT datname FROM pg_database WHERE datistemplate=false ORDER BY datname")->fetchAll(PDO::FETCH_COLUMN),
        'sqlite' => ['main'],
        default  => [],
    };
}

function dbTables(PDO $pdo, string $drv): array {
    return match($drv) {
        'mysql'  => $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN),
        'pgsql'  => $pdo->query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")->fetchAll(PDO::FETCH_COLUMN),
        'sqlite' => $pdo->query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN),
        default  => [],
    };
}

function dbUse(PDO $pdo, string $drv, string $db): void {
    if ($drv === 'mysql') $pdo->exec("USE " . bt($db));
}

function dbDescribe(PDO $pdo, string $drv, string $table): array {
    return match($drv) {
        'mysql'  => $pdo->query("DESCRIBE " . bt($table))->fetchAll(),
        'pgsql'  => $pdo->query(
            "SELECT column_name AS \"Field\", data_type AS \"Type\",
                    is_nullable AS \"Null\", '' AS \"Key\",
                    column_default AS \"Default\", '' AS \"Extra\"
             FROM information_schema.columns
             WHERE table_name=" . $pdo->quote($table) . " ORDER BY ordinal_position"
        )->fetchAll(),
        'sqlite' => array_map(fn($r) => [
            'Field'   => $r['name'],
            'Type'    => $r['type'],
            'Null'    => $r['notnull'] ? 'NO' : 'YES',
            'Key'     => $r['pk'] ? 'PRI' : '',
            'Default' => $r['dflt_value'],
            'Extra'   => '',
        ], $pdo->query("PRAGMA table_info(" . bt($table) . ")")->fetchAll()),
        default => [],
    };
}

function qt(string $drv, string $name): string {
    return $drv === 'pgsql'
        ? '"' . str_replace('"', '""', $name) . '"'
        : bt($name);
}

// Returns [tableName => ['rows' => int, 'approx' => bool]]  — single query per driver
function dbTableRowCounts(PDO $pdo, string $drv, string $db, array $tables): array {
    $counts = [];
    try {
        switch ($drv) {
            case 'mysql':
                $stmt = $pdo->prepare(
                    "SELECT TABLE_NAME, TABLE_ROWS, ENGINE
                     FROM information_schema.TABLES
                     WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'"
                );
                $stmt->execute([$db]);
                $needsCheck = []; // tables where estimate = 0 but might not be empty
                foreach ($stmt->fetchAll() as $r) {
                    $approx = in_array(strtolower($r['ENGINE'] ?? ''), ['innodb', 'rocksdb']);
                    $est    = max(0, (int)$r['TABLE_ROWS']);
                    if ($approx && $est === 0) {
                        // InnoDB estimate of 0 is unreliable — verify with a quick EXISTS check
                        $needsCheck[] = $r['TABLE_NAME'];
                        $counts[$r['TABLE_NAME']] = ['rows' => 0, 'approx' => true, 'unverified' => true];
                    } else {
                        $counts[$r['TABLE_NAME']] = ['rows' => $est, 'approx' => $approx];
                    }
                }
                // Batch-verify suspected-empty InnoDB tables (one query each, but only 1 row read)
                foreach ($needsCheck as $tbl) {
                    $exists = (int)$pdo->query(
                        "SELECT EXISTS(SELECT 1 FROM " . bt($tbl) . " LIMIT 1)"
                    )->fetchColumn();
                    if ($exists) {
                        // Table has data — show as non-empty but count unknown
                        $counts[$tbl] = ['rows' => -1, 'approx' => true]; // -1 = "has rows, unknown count"
                    } else {
                        $counts[$tbl] = ['rows' => 0, 'approx' => true];
                    }
                }
                break;

            case 'pgsql':
                $stmt = $pdo->query(
                    "SELECT relname AS t, n_live_tup AS rows
                     FROM pg_stat_user_tables WHERE schemaname='public'"
                );
                foreach ($stmt->fetchAll() as $r) {
                    $counts[$r['t']] = ['rows' => max(0, (int)$r['rows']), 'approx' => true];
                }
                break;

            case 'sqlite':
                if (empty($tables)) break;
                // Build UNION ALL in one shot
                $parts = array_map(
                    fn($t) => "SELECT " . $pdo->quote($t) . " AS t, COUNT(*) AS rows FROM " . bt($t),
                    $tables
                );
                $stmt = $pdo->query(implode(" UNION ALL ", $parts));
                foreach ($stmt->fetchAll() as $r) {
                    $counts[$r['t']] = ['rows' => (int)$r['rows'], 'approx' => false];
                }
                break;
        }
    } catch (PDOException) {}
    return $counts;
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

function bt(string $name): string {
    return '`' . str_replace('`', '``', $name) . '`';
}
function h($v): string {
    return htmlspecialchars((string)($v ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function u(array $p = []): string {
    $base = htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8');
    return $p ? $base . '?' . http_build_query($p) : $base;
}
function ok(?string $name, array $list): bool {
    return $name !== null && in_array($name, $list, true);
}

// ── BOOT ──────────────────────────────────────────────────────────────────────

$pdo    = null;
$driver = 'mysql';
$error  = '';

if (isset($_GET['logout'])) { session_destroy(); header('Location: ' . $_SERVER['PHP_SELF']); exit; }

// Login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $host = trim($_POST['host'] ?? 'localhost');
    $port = max(1, min(65535, (int)($_POST['port'] ?? 3306)));
    $user = trim($_POST['username'] ?? '');
    $pass = $_POST['password'] ?? '';
    $drv  = $_POST['driver']   ?? 'auto';
    try {
        if ($drv === 'auto') {
            ['driver' => $drv, 'pdo' => $pdo] = autoDetect($host, $port, $user, $pass);
        } else {
            $pdo = makePdo($drv, $host, $port, $user, $pass);
        }
        $_SESSION['hadminer'] = ['host'=>$host,'port'=>$port,'username'=>$user,'password'=>$pass,'driver'=>$drv];
        header('Location: ' . $_SERVER['PHP_SELF']); exit;
    } catch (PDOException $e) {
        $error = 'Connection failed: ' . $e->getMessage();
    }
}

// Restore session
if (isset($_SESSION['hadminer'])) {
    $s = $_SESSION['hadminer'];
    $driver = $s['driver'] ?? 'mysql';
    try { $pdo = makePdo($driver, $s['host'], $s['port'] ?? 3306, $s['username'], $s['password']); }
    catch (PDOException $e) { session_destroy(); $error = 'Session expired. Please reconnect.'; }
}

// ── URL PARAMS ────────────────────────────────────────────────────────────────

$currentDb    = isset($_GET['db'])    ? (string)$_GET['db']    : null;
$currentTable = isset($_GET['table']) ? (string)$_GET['table'] : null;
$view         = in_array($_GET['view'] ?? '', ['data','structure','sql']) ? $_GET['view'] : 'data';
$page         = max(1, (int)($_GET['page'] ?? 1));

// ── SQL EXECUTION ─────────────────────────────────────────────────────────────

$sqlQuery    = $_POST['sql'] ?? $_SESSION['hadminer']['last_sql'] ?? '';
$sqlResults  = null;
$sqlCols     = [];
$sqlError    = '';
$sqlTime     = 0;
$sqlAffected = null;

if ($pdo && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sql_exec'])) {
    $sqlQuery = trim($_POST['sql'] ?? '');
    $view     = 'sql';

    if ($sqlQuery !== '') {
        // History
        $hist = $_SESSION['hadminer']['sql_history'] ?? [];
        $hist = array_values(array_filter($hist, fn($q) => $q !== $sqlQuery));
        array_unshift($hist, $sqlQuery);
        $_SESSION['hadminer']['sql_history'] = array_slice($hist, 0, QUERY_HISTORY_MAX);
        $_SESSION['hadminer']['last_sql']    = $sqlQuery;

        $t0 = microtime(true);
        try {
            // Set DB context
            if ($currentDb) {
                if ($driver === 'mysql') {
                    $pdo->exec("USE " . bt($currentDb));
                } elseif ($driver === 'pgsql') {
                    $s   = $_SESSION['hadminer'];
                    $pdo = makePdo('pgsql', $s['host'], $s['port'], $s['username'], $s['password'], $currentDb);
                }
            }
            $stmt = $pdo->prepare($sqlQuery);
            $stmt->execute();
            $sqlTime = round((microtime(true) - $t0) * 1000, 2);
            if ($stmt->columnCount() > 0) {
                $sqlResults = $stmt->fetchAll();
                $sqlCols    = empty($sqlResults) ? [] : array_keys($sqlResults[0]);
            } else {
                $sqlAffected = $stmt->rowCount();
            }
        } catch (PDOException $e) {
            $sqlTime  = round((microtime(true) - $t0) * 1000, 2);
            $sqlError = $e->getMessage();
        }
    }
}

$sqlHistory = $_SESSION['hadminer']['sql_history'] ?? [];

// ── DATA FETCH ────────────────────────────────────────────────────────────────

$databases      = [];
$tables         = [];
$tableRowCounts = []; // tableName => ['rows'=>int,'approx'=>bool]
$tableData      = [];
$tableColumns   = [];
$tableStructure = [];
$hashColumns    = []; // colName => detected hash type
$totalRows      = 0;
$totalPages     = 1;

if ($pdo) {
    try {
        $databases = dbDatabases($pdo, $driver);

        if ($currentDb && ok($currentDb, $databases)) {
            if ($driver === 'pgsql') {
                $s = $_SESSION['hadminer'];
                $pdo = makePdo('pgsql', $s['host'], $s['port'], $s['username'], $s['password'], $currentDb);
            } else {
                dbUse($pdo, $driver, $currentDb);
            }

            $tables         = dbTables($pdo, $driver);
            $tableRowCounts = dbTableRowCounts($pdo, $driver, $currentDb, $tables);

            if ($currentTable && ok($currentTable, $tables)) {
                $tq = qt($driver, $currentTable);

                $tableStructure = dbDescribe($pdo, $driver, $currentTable);
                $totalRows      = (int)$pdo->query("SELECT COUNT(*) FROM {$tq}")->fetchColumn();
                $totalPages     = max(1, (int)ceil($totalRows / ROWS_PER_PAGE));
                $page           = min($page, $totalPages);

                $offset    = ($page - 1) * ROWS_PER_PAGE;
                $tableData = $pdo->query("SELECT * FROM {$tq} LIMIT " . ROWS_PER_PAGE . " OFFSET {$offset}")->fetchAll();
                $tableColumns = empty($tableData) ? array_column($tableStructure, 'Field') : array_keys($tableData[0]);

                // Hash column analysis
                foreach ($tableColumns as $col) {
                    $t = analyzeColumnHashes($col, array_column($tableData, $col));
                    if ($t !== null) $hashColumns[$col] = $t;
                }
            } else {
                $currentTable = null;
            }
        } else {
            $currentDb = null;
        }
    } catch (PDOException $e) {
        $error = $e->getMessage();
    }
}

$driverLabel = match($driver) {
    'mysql'  => 'MySQL',
    'pgsql'  => 'PostgreSQL',
    'sqlite' => 'SQLite',
    default  => strtoupper($driver),
};
$driverIcon = match($driver) {
    'mysql'  => '🐬',
    'pgsql'  => '🐘',
    'sqlite' => '📁',
    default  => '🗄',
};
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= APP_NAME ?><?= $currentDb ? ' · ' . h($currentDb) : '' ?><?= $currentTable ? ' · ' . h($currentTable) : '' ?></title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg:#0f1117;
  --surface:#1a1d27;
  --surface2:#21252f;
  --border:#2d3142;
  --accent:#6c63ff;
  --accent-dim:rgba(108,99,255,.12);
  --text:#e2e8f0;
  --muted:#64748b;
  --green:#10b981;
  --yellow:#f59e0b;
  --red:#ef4444;
  --orange:#f97316;
  --r:8px;
  --font:'Segoe UI',system-ui,-apple-system,sans-serif;
  --mono:'Cascadia Code','Fira Code',Consolas,monospace;
}

body{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;font-size:14px;line-height:1.5}

/* ── LOGIN ─────────────────────────────────────────── */
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:440px}
.login-logo{text-align:center;margin-bottom:32px}
.login-logo h1{font-size:34px;font-weight:800;background:linear-gradient(135deg,var(--accent),#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.login-logo p{color:var(--muted);font-size:13px;margin-top:4px}

/* ── FORMS ─────────────────────────────────────────── */
.form-group{margin-bottom:16px}
label{display:block;font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}
input[type=text],input[type=password],input[type=number],select,textarea{
  width:100%;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);
  color:var(--text);padding:10px 14px;font-size:14px;font-family:var(--font);
  transition:border-color .2s;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--accent)}
select option{background:var(--surface2)}
.form-row{display:grid;grid-template-columns:1fr 80px;gap:8px}

.btn{display:inline-flex;align-items:center;gap:6px;background:var(--accent);color:#fff;
  border:none;border-radius:var(--r);padding:10px 20px;font-size:14px;font-weight:600;
  cursor:pointer;text-decoration:none;transition:background .15s;font-family:var(--font);white-space:nowrap}
.btn:hover{background:#5a52d5}
.btn-full{width:100%;justify-content:center}
.btn-sm{padding:5px 12px;font-size:12px}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--surface2);color:var(--text)}
.btn-green{background:var(--green)}
.btn-green:hover{background:#059669}

.alert{padding:12px 16px;border-radius:var(--r);margin-bottom:20px;font-size:13px}
.alert-err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5}
.alert-ok{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);color:#6ee7b7}

/* ── LAYOUT ─────────────────────────────────────────── */
.layout{display:grid;grid-template-columns:240px 1fr;min-height:100vh}

/* ── SIDEBAR ─────────────────────────────────────────── */
.sidebar{background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;display:flex;flex-direction:column}
.sidebar-head{padding:16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
.logo{font-size:17px;font-weight:800;background:linear-gradient(135deg,var(--accent),#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.drv-badge{font-size:11px;background:var(--surface2);border:1px solid var(--border);padding:2px 7px;border-radius:20px;color:var(--muted);margin-left:auto;white-space:nowrap}
.sidebar-body{padding:10px;flex:1}
.sidebar-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);padding:8px 10px 4px}
.s-item{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:6px;color:var(--muted);text-decoration:none;font-size:13px;transition:all .15s;cursor:pointer;user-select:none}
.s-item:hover{background:var(--surface2);color:var(--text)}
.s-item.active{background:var(--accent-dim);color:var(--accent)}
.s-item svg{width:14px;height:14px;flex-shrink:0;opacity:.7}

/* ── MAIN ────────────────────────────────────────────── */
.main{overflow:auto;display:flex;flex-direction:column;min-width:0}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:13px 24px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-shrink:0}
.breadcrumb{display:flex;align-items:center;gap:5px;font-size:13px;color:var(--muted);flex-wrap:wrap}
.breadcrumb a{color:var(--muted);text-decoration:none;transition:color .15s}
.breadcrumb a:hover{color:var(--text)}
.breadcrumb .sep{opacity:.4}
.breadcrumb .cur{color:var(--text);font-weight:600}
.srv-info{display:flex;align-items:center;gap:10px;font-size:12px;color:var(--muted);white-space:nowrap}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block;flex-shrink:0}

.content{padding:24px;flex:1}

/* ── CARD ────────────────────────────────────────────── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.card-head{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.card-title{font-size:14px;font-weight:700;display:flex;align-items:center;gap:8px}
.badge{background:var(--surface2);color:var(--muted);padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600}

/* ── DB GRID ─────────────────────────────────────────── */
.db-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px;padding:20px}
.db-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);padding:16px 14px;text-decoration:none;color:var(--text);transition:all .2s;display:flex;flex-direction:column;gap:8px}
.db-card:hover{border-color:var(--accent);background:var(--accent-dim);transform:translateY(-2px)}
.db-card-icon{font-size:22px}
.db-card-name{font-weight:600;font-size:13px;word-break:break-all}

/* ── TABLE LIST ──────────────────────────────────────── */
.table-list{padding:8px}
.table-list-search{padding:8px 8px 4px;position:sticky;top:0;background:var(--surface);z-index:2}
.table-list-search input{padding:7px 12px;font-size:13px}
.t-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:6px;text-decoration:none;color:var(--text);transition:background .15s;font-size:13px}
.t-item:hover{background:var(--surface2)}
.t-item.active{background:var(--accent-dim);color:var(--accent)}
.t-item.empty-tbl{opacity:.45}
.t-item.empty-tbl:hover{opacity:1}
.t-icon{color:var(--muted);font-size:12px;flex-shrink:0}
.t-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.t-count{font-size:11px;font-family:var(--mono);color:var(--muted);flex-shrink:0;white-space:nowrap}
.t-count.has-rows{color:var(--green)}
.t-count.empty{color:var(--muted)}
.t-approx{font-size:9px;opacity:.6}

/* ── TABS ────────────────────────────────────────────── */
.tabs{display:flex;padding:0 20px;border-bottom:1px solid var(--border)}
.tab{padding:11px 16px;font-size:13px;font-weight:500;color:var(--muted);text-decoration:none;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .15s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}

/* ── DATA TABLE ──────────────────────────────────────── */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--surface2);padding:9px 14px;text-align:left;font-weight:700;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;border-bottom:1px solid var(--border)}
th .th-inner{display:flex;align-items:center;gap:6px}
td{padding:9px 14px;border-bottom:1px solid var(--border);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono);font-size:12px}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.025)}
.null{color:var(--muted);font-style:italic}

/* ── HASH BADGES ─────────────────────────────────────── */
.hash-th{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;vertical-align:middle;text-transform:none;letter-spacing:0}
.hw{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.3)}   /* weak */
.hm{background:rgba(249,115,22,.15);color:#fdba74;border:1px solid rgba(249,115,22,.3)} /* medium */
.hs{background:rgba(16,185,129,.15);color:#6ee7b7;border:1px solid rgba(16,185,129,.3)} /* strong */
.hash-cell{display:inline-flex;align-items:center;gap:5px;width:100%}
.hash-tag{flex-shrink:0;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;text-transform:uppercase;letter-spacing:.03em;cursor:help}

/* ── PAGINATION ──────────────────────────────────────── */
.pager{display:flex;align-items:center;gap:5px;padding:14px 20px;border-top:1px solid var(--border);flex-wrap:wrap}
.pager-info{color:var(--muted);font-size:12px;margin-right:auto}
.pg{min-width:30px;height:30px;display:flex;align-items:center;justify-content:center;border-radius:6px;text-decoration:none;color:var(--muted);font-size:13px;border:1px solid var(--border);transition:all .15s;padding:0 7px}
.pg:hover{background:var(--surface2);color:var(--text)}
.pg.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.pg.off{opacity:.3;pointer-events:none}

/* ── SQL EDITOR ──────────────────────────────────────── */
.sql-editor-wrap{padding:20px;display:flex;flex-direction:column;gap:12px}
.sql-editor-top{display:flex;gap:10px;align-items:flex-start}
textarea.sql-input{resize:vertical;min-height:120px;font-family:var(--mono);font-size:13px;line-height:1.6;flex:1;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--text);padding:12px 14px}
textarea.sql-input:focus{border-color:var(--accent)}
.sql-actions{display:flex;flex-direction:column;gap:8px;flex-shrink:0}
.sql-meta{display:flex;align-items:center;gap:12px;font-size:12px;color:var(--muted)}
.sql-time{font-family:var(--mono)}
.sql-result-info{font-weight:600}
.sql-result-info.ok{color:var(--green)}
.sql-result-info.err{color:var(--red)}

/* ── HISTORY DROPDOWN ────────────────────────────────── */
.history-wrap{position:relative;display:inline-block}
.history-btn{cursor:pointer}
.history-menu{display:none;position:absolute;right:0;top:calc(100% + 4px);background:var(--surface);border:1px solid var(--border);border-radius:var(--r);width:420px;max-height:260px;overflow-y:auto;z-index:100;box-shadow:0 8px 24px rgba(0,0,0,.4)}
.history-wrap:focus-within .history-menu,
.history-menu:hover{display:block}
.history-item{padding:9px 14px;font-family:var(--mono);font-size:11px;color:var(--muted);cursor:pointer;border-bottom:1px solid var(--border);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;transition:background .1s}
.history-item:last-child{border-bottom:none}
.history-item:hover{background:var(--surface2);color:var(--text)}

/* ── EMPTY ───────────────────────────────────────────── */
.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.empty-icon{font-size:44px;margin-bottom:14px}
.empty h3{font-size:16px;color:var(--text);margin-bottom:6px}

/* ── STRUCTURE KEYS ──────────────────────────────────── */
.key-pri{color:var(--accent);font-weight:700}
.key-uni{color:var(--green);font-weight:700}
.key-mul{color:var(--muted)}

@media(max-width:768px){
  .layout{grid-template-columns:1fr}
  .sidebar{display:none}
}
</style>
</head>
<body>

<?php if (!$pdo): ?>
<!-- ══════════════ LOGIN ══════════════ -->
<div class="login-wrap">
  <div class="login-card">
    <div class="login-logo">
      <h1><?= APP_NAME ?></h1>
      <p>Multi-engine Database Manager</p>
    </div>

    <?php if ($error): ?>
    <div class="alert alert-err"><?= h($error) ?></div>
    <?php endif; ?>

    <form method="POST" autocomplete="on">
      <div class="form-group">
        <label>Driver</label>
        <select name="driver" id="drv-sel" onchange="onDrvChange(this.value)">
          <option value="auto">Auto-detect</option>
          <option value="mysql">🐬 MySQL / MariaDB</option>
          <option value="pgsql">🐘 PostgreSQL</option>
          <option value="sqlite">📁 SQLite (file path)</option>
        </select>
      </div>
      <div class="form-group" id="host-group">
        <label>Host &amp; Port</label>
        <div class="form-row">
          <input type="text" name="host" id="host-inp" value="localhost" placeholder="localhost" autocomplete="off">
          <input type="number" name="port" value="3306" placeholder="3306" min="1" max="65535">
        </div>
      </div>
      <div id="cred-group">
        <div class="form-group">
          <label>Username</label>
          <input type="text" name="username" placeholder="root" autocomplete="username">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" name="password" placeholder="••••••••" autocomplete="current-password">
        </div>
      </div>
      <button type="submit" name="login" class="btn btn-full">Connect →</button>
    </form>
  </div>
</div>
<script>
function onDrvChange(v) {
  const hostGrp = document.getElementById('host-group');
  const credGrp = document.getElementById('cred-group');
  const hostInp = document.getElementById('host-inp');
  if (v === 'sqlite') {
    hostGrp.querySelector('label').textContent = 'File Path';
    hostInp.placeholder = '/path/to/database.db';
    hostInp.value = '';
    credGrp.style.display = 'none';
  } else {
    hostGrp.querySelector('label').textContent = 'Host & Port';
    hostInp.placeholder = 'localhost';
    hostInp.value = 'localhost';
    credGrp.style.display = '';
  }
}
</script>

<?php else: ?>
<!-- ══════════════ APP ══════════════ -->
<div class="layout">

  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="sidebar-head">
      <span class="logo"><?= APP_NAME ?></span>
      <span class="drv-badge"><?= $driverIcon ?> <?= $driverLabel ?></span>
    </div>
    <div class="sidebar-body">
      <div class="sidebar-label">Databases</div>
      <?php foreach ($databases as $db): ?>
        <a href="<?= u(['db'=>$db]) ?>" class="s-item <?= $currentDb===$db?'active':'' ?>">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0018 0V5"/>
            <path d="M3 12a9 3 0 0018 0"/>
          </svg>
          <?= h($db) ?>
        </a>
      <?php endforeach; ?>
    </div>
  </aside>

  <!-- Main -->
  <div class="main">
    <div class="topbar">
      <div class="breadcrumb">
        <a href="<?= u() ?>">Home</a>
        <?php if ($currentDb): ?>
          <span class="sep">/</span>
          <a href="<?= u(['db'=>$currentDb]) ?>"><?= h($currentDb) ?></a>
        <?php endif; ?>
        <?php if ($currentTable): ?>
          <span class="sep">/</span>
          <span class="cur"><?= h($currentTable) ?></span>
        <?php endif; ?>
      </div>
      <div class="srv-info">
        <span class="dot"></span>
        <?php if ($driver !== 'sqlite'): ?>
          <?= h($_SESSION['hadminer']['username']) ?>@<?= h($_SESSION['hadminer']['host']) ?>
        <?php else: ?>
          <?= h($_SESSION['hadminer']['host']) ?>
        <?php endif; ?>
        <a href="<?= u(['logout'=>1]) ?>" class="btn btn-ghost btn-sm">Logout</a>
      </div>
    </div>

    <div class="content">

      <?php if ($error): ?>
      <div class="alert alert-err"><?= h($error) ?></div>
      <?php endif; ?>

      <?php if (!$currentDb): ?>
      <!-- ── DB LIST ── -->
      <div class="card">
        <div class="card-head">
          <div class="card-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0018 0V5"/>
              <path d="M3 12a9 3 0 0018 0"/>
            </svg>
            Databases <span class="badge"><?= count($databases) ?></span>
          </div>
        </div>
        <?php if (empty($databases)): ?>
          <div class="empty"><div class="empty-icon">🗄</div><h3>No databases</h3></div>
        <?php else: ?>
          <div class="db-grid">
            <?php foreach ($databases as $db): ?>
              <a href="<?= u(['db'=>$db]) ?>" class="db-card">
                <div class="db-card-icon"><?= $driverIcon ?></div>
                <div class="db-card-name"><?= h($db) ?></div>
              </a>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </div>

      <?php elseif (!$currentTable): ?>
      <!-- ── TABLE LIST + SQL at DB level ── -->
      <?php
        $emptyCount    = count(array_filter($tableRowCounts, fn($r) => $r['rows'] === 0));
        $nonEmptyCount = count($tables) - $emptyCount;
      ?>
      <div class="card" style="margin-bottom:20px">
        <div class="card-head">
          <div class="card-title">
            📋 <?= h($currentDb) ?>
            <span class="badge"><?= count($tables) ?> tables</span>
            <?php if ($emptyCount > 0): ?>
              <span class="badge" style="color:var(--muted)"><?= $emptyCount ?> empty</span>
            <?php endif; ?>
          </div>
          <div style="display:flex;gap:8px;font-size:12px;color:var(--muted)">
            <label style="display:flex;align-items:center;gap:5px;cursor:pointer;text-transform:none;letter-spacing:0;font-size:12px;font-weight:400">
              <input type="checkbox" id="hide-empty" onchange="filterTables()" style="width:auto;accent-color:var(--accent)">
              Hide empty
            </label>
          </div>
        </div>
        <?php if (empty($tables)): ?>
          <div class="empty"><div class="empty-icon">📭</div><h3>No tables</h3></div>
        <?php else: ?>
          <div class="table-list-search">
            <input type="text" id="tbl-search" placeholder="Filter tables…" oninput="filterTables()" style="width:100%">
          </div>
          <div class="table-list" id="tbl-list">
            <?php foreach ($tables as $tbl):
              $rc      = $tableRowCounts[$tbl] ?? null;
              $rows    = $rc ? $rc['rows'] : null;
              $approx  = $rc ? $rc['approx'] : false;
              $isEmpty = $rows === 0; // -1 = has data (count unknown), null = stats unavailable
            ?>
              <a href="<?= u(['db'=>$currentDb,'table'=>$tbl]) ?>"
                 class="t-item <?= $isEmpty ? 'empty-tbl' : '' ?>"
                 data-name="<?= h(strtolower($tbl)) ?>"
                 data-empty="<?= $isEmpty ? '1' : '0' ?>">
                <span class="t-icon">▤</span>
                <span class="t-name"><?= h($tbl) ?></span>
                <?php if ($rc !== null): ?>
                  <span class="t-count <?= $isEmpty ? 'empty' : 'has-rows' ?>">
                    <?php if ($rows === -1): ?>
                      <span class="t-approx">✓</span>
                    <?php elseif ($isEmpty): ?>
                      —
                    <?php else: ?>
                      <?= $approx ? '<span class="t-approx">~</span>' : '' ?><?= number_format($rows) ?>
                    <?php endif; ?>
                  </span>
                <?php endif; ?>
              </a>
            <?php endforeach; ?>
          </div>
          <div id="tbl-no-match" style="display:none" class="empty" style="padding:30px">
            <div class="empty-icon">🔍</div><h3>No tables match</h3>
          </div>
        <?php endif; ?>
      </div>
      <script>
      function filterTables() {
        var q      = (document.getElementById('tbl-search').value || '').toLowerCase();
        var hideEm = document.getElementById('hide-empty').checked;
        var items  = document.querySelectorAll('#tbl-list .t-item');
        var shown  = 0;
        items.forEach(function(el) {
          var nameMatch  = !q || el.dataset.name.includes(q);
          var emptyMatch = !hideEm || el.dataset.empty === '0';
          var visible    = nameMatch && emptyMatch;
          el.style.display = visible ? '' : 'none';
          if (visible) shown++;
        });
        document.getElementById('tbl-no-match').style.display = shown === 0 ? '' : 'none';
      }
      </script>

      <!-- SQL Editor (DB level) -->
      <?= renderSqlEditor($currentDb, null, $sqlQuery, $sqlResults, $sqlCols, $sqlError, $sqlTime, $sqlAffected, $sqlHistory, $view, $driver) ?>

      <?php else: ?>
      <!-- ── TABLE VIEW ── -->
      <div class="card">
        <div class="card-head">
          <div class="card-title">
            ▤ <?= h($currentTable) ?>
            <?php if ($view === 'data'): ?>
              <span class="badge"><?= number_format($totalRows) ?> rows</span>
            <?php elseif ($view === 'structure'): ?>
              <span class="badge"><?= count($tableStructure) ?> cols</span>
            <?php endif; ?>
            <?php if (!empty($hashColumns)): ?>
              <span class="badge" style="background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.3)">
                🔑 <?= count($hashColumns) ?> hash col<?= count($hashColumns)>1?'s':'' ?>
              </span>
            <?php endif; ?>
          </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
          <a href="<?= u(['db'=>$currentDb,'table'=>$currentTable,'view'=>'data']) ?>"
             class="tab <?= $view==='data'?'active':'' ?>">Data</a>
          <a href="<?= u(['db'=>$currentDb,'table'=>$currentTable,'view'=>'structure']) ?>"
             class="tab <?= $view==='structure'?'active':'' ?>">Structure</a>
          <a href="<?= u(['db'=>$currentDb,'table'=>$currentTable,'view'=>'sql']) ?>"
             class="tab <?= $view==='sql'?'active':'' ?>">SQL</a>
        </div>

        <?php if ($view === 'structure'): ?>
        <!-- STRUCTURE -->
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>Column</th><th>Type</th><th>Null</th><th>Key</th><th>Default</th><th>Extra</th><th>Hash</th>
            </tr></thead>
            <tbody>
            <?php foreach ($tableStructure as $col): ?>
              <?php $htype = $hashColumns[$col['Field']] ?? null; ?>
              <tr>
                <td><strong><?= h($col['Field']) ?></strong></td>
                <td><?= h($col['Type']) ?></td>
                <td><?= $col['Null']==='YES'?'<span style="color:var(--yellow)">YES</span>':'<span style="color:var(--muted)">NO</span>' ?></td>
                <td><?php
                  if     ($col['Key']==='PRI') echo '<span class="key-pri">PRI ★</span>';
                  elseif ($col['Key']==='UNI') echo '<span class="key-uni">UNI</span>';
                  elseif ($col['Key']==='MUL') echo '<span class="key-mul">MUL</span>';
                  else echo '<span style="color:var(--muted)">—</span>';
                ?></td>
                <td><?= $col['Default']!==null?h($col['Default']):'<span class="null">NULL</span>' ?></td>
                <td><?= h($col['Extra'])?:'<span style="color:var(--muted)">—</span>' ?></td>
                <td><?php if ($htype): ?>
                  <span class="hash-th <?= hashStrength($htype) ?>" title="Detected hash algorithm">
                    🔑 <?= h($htype) ?>
                  </span>
                <?php else: echo '<span style="color:var(--muted)">—</span>'; endif; ?></td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>

        <?php elseif ($view === 'sql'): ?>
        <!-- SQL TAB (table level) -->
        <?= renderSqlEditor($currentDb, $currentTable, $sqlQuery, $sqlResults, $sqlCols, $sqlError, $sqlTime, $sqlAffected, $sqlHistory, $view, $driver) ?>

        <?php else: ?>
        <!-- DATA -->
        <?php if ($totalRows === 0): ?>
          <div class="empty"><div class="empty-icon">📭</div><h3>Table is empty</h3></div>
        <?php else: ?>
          <div class="table-wrap">
            <table>
              <thead><tr>
                <?php foreach ($tableColumns as $col):
                  $htype = $hashColumns[$col] ?? null; ?>
                <th>
                  <div class="th-inner">
                    <?= h($col) ?>
                    <?php if ($htype): ?>
                      <span class="hash-th <?= hashStrength($htype) ?>" title="Hash type: <?= h($htype) ?>">
                        🔑 <?= h($htype) ?>
                      </span>
                    <?php endif; ?>
                  </div>
                </th>
                <?php endforeach; ?>
              </tr></thead>
              <tbody>
              <?php foreach ($tableData as $row): ?>
                <tr>
                <?php foreach ($row as $col => $val):
                  $htype = $hashColumns[$col] ?? null; ?>
                  <td title="<?= h($val) ?>">
                    <?php if ($val === null): ?>
                      <span class="null">NULL</span>
                    <?php elseif ($htype): ?>
                      <?php $detected = detectHashType((string)$val); ?>
                      <span class="hash-cell">
                        <span class="hash-tag <?= $detected ? hashStrength($detected) : '' ?>"
                              title="<?= $detected ? h($detected) : 'unknown' ?>">
                          <?= $detected ? h($detected) : '?' ?>
                        </span>
                        <?= h($val) ?>
                      </span>
                    <?php else: ?>
                      <?= h($val) ?>
                    <?php endif; ?>
                  </td>
                <?php endforeach; ?>
                </tr>
              <?php endforeach; ?>
              </tbody>
            </table>
          </div>

          <?php if ($totalPages > 1): ?>
          <div class="pager">
            <span class="pager-info">
              Rows <?= number_format(($page-1)*ROWS_PER_PAGE+1) ?>–<?= number_format(min($page*ROWS_PER_PAGE,$totalRows)) ?>
              of <?= number_format($totalRows) ?>
            </span>
            <?php $pq = ['db'=>$currentDb,'table'=>$currentTable,'view'=>$view]; ?>
            <a href="<?= u($pq+['page'=>1]) ?>"          class="pg <?= $page>1?'':'off' ?>">«</a>
            <a href="<?= u($pq+['page'=>$page-1]) ?>"    class="pg <?= $page>1?'':'off' ?>">‹</a>
            <?php for ($p=max(1,$page-2);$p<=min($totalPages,$page+2);$p++): ?>
              <a href="<?= u($pq+['page'=>$p]) ?>" class="pg <?= $p===$page?'on':'' ?>"><?= $p ?></a>
            <?php endfor; ?>
            <a href="<?= u($pq+['page'=>$page+1]) ?>"    class="pg <?= $page<$totalPages?'':'off' ?>">›</a>
            <a href="<?= u($pq+['page'=>$totalPages]) ?>" class="pg <?= $page<$totalPages?'':'off' ?>">»</a>
          </div>
          <?php endif; ?>
        <?php endif; ?>
        <?php endif; ?>

      </div><!-- /card -->
      <?php endif; ?>

    </div><!-- /content -->
  </div><!-- /main -->
</div><!-- /layout -->
<?php endif; ?>

<?php
// ── SQL EDITOR RENDER FUNCTION ────────────────────────────────────────────────
function renderSqlEditor(
    ?string $db, ?string $table,
    string $sqlQuery, $sqlResults, array $sqlCols,
    string $sqlError, float $sqlTime, $sqlAffected,
    array $history, string $view, string $driver
): string {
    $uParams = array_filter(['db'=>$db,'table'=>$table,'view'=>'sql']);
    $action  = htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8')
             . ($uParams ? '?' . http_build_query($uParams) : '');
    ob_start(); ?>

<div class="card" style="<?= $table ? '' : 'margin-top:0' ?>">
  <div class="card-head">
    <div class="card-title">⚡ SQL Query<?= $table ? ' — ' . htmlspecialchars($table, ENT_QUOTES, 'UTF-8') : ($db ? ' — ' . htmlspecialchars($db, ENT_QUOTES, 'UTF-8') : '') ?></div>
    <?php if (!empty($history)): ?>
    <div class="history-wrap" tabindex="0">
      <button type="button" class="btn btn-ghost btn-sm history-btn">History ▾</button>
      <div class="history-menu" id="hist-menu">
        <?php foreach ($history as $i => $q): ?>
          <div class="history-item" onclick="fillSql(<?= $i ?>)"><?= htmlspecialchars($q, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endforeach; ?>
      </div>
    </div>
    <?php endif; ?>
  </div>

  <form method="POST" action="<?= $action ?>">
    <?php if ($db): ?><input type="hidden" name="db" value="<?= htmlspecialchars($db, ENT_QUOTES, 'UTF-8') ?>"><?php endif; ?>
    <?php if ($table): ?><input type="hidden" name="table" value="<?= htmlspecialchars($table, ENT_QUOTES, 'UTF-8') ?>"><?php endif; ?>
    <div class="sql-editor-wrap">
      <div class="sql-editor-top">
        <textarea name="sql" id="sql-inp" class="sql-input"
          placeholder="SELECT * FROM ...&#10;Press Ctrl+Enter to execute"
          spellcheck="false"><?= htmlspecialchars($sqlQuery, ENT_QUOTES, 'UTF-8') ?></textarea>
        <div class="sql-actions">
          <button type="submit" name="sql_exec" value="1" class="btn btn-green">▶ Run</button>
          <button type="button" class="btn btn-ghost btn-sm" onclick="document.getElementById('sql-inp').value=''">Clear</button>
          <?php if ($table): ?>
          <button type="button" class="btn btn-ghost btn-sm"
            onclick="document.getElementById('sql-inp').value='SELECT * FROM <?= addslashes(htmlspecialchars($table)) ?> LIMIT 100'">
            Quick SELECT
          </button>
          <?php endif; ?>
        </div>
      </div>

      <?php if ($sqlError): ?>
      <div class="alert alert-err" style="margin:0">
        <strong>Error</strong> · <?= htmlspecialchars($sqlTime, ENT_QUOTES, 'UTF-8') ?>ms<br>
        <?= htmlspecialchars($sqlError, ENT_QUOTES, 'UTF-8') ?>
      </div>

      <?php elseif ($sqlAffected !== null): ?>
      <div class="alert alert-ok" style="margin:0">
        ✓ Query OK — <?= $sqlAffected ?> row<?= $sqlAffected !== 1 ? 's' : '' ?> affected
        <span style="float:right;opacity:.6"><?= htmlspecialchars($sqlTime, ENT_QUOTES, 'UTF-8') ?>ms</span>
      </div>

      <?php elseif ($sqlResults !== null): ?>
      <div class="sql-meta">
        <span class="sql-result-info ok">✓ <?= count($sqlResults) ?> row<?= count($sqlResults)!==1?'s':'' ?> returned</span>
        <span class="sql-time"><?= htmlspecialchars($sqlTime, ENT_QUOTES, 'UTF-8') ?>ms</span>
      </div>

      <?php if (empty($sqlResults)): ?>
        <div class="empty" style="padding:30px"><div class="empty-icon">📭</div><h3>No results</h3></div>
      <?php else: ?>
        <div class="table-wrap" style="max-height:420px;overflow-y:auto">
          <table>
            <thead><tr>
              <?php foreach ($sqlCols as $c): ?><th><?= htmlspecialchars($c, ENT_QUOTES, 'UTF-8') ?></th><?php endforeach; ?>
            </tr></thead>
            <tbody>
            <?php foreach ($sqlResults as $row): ?>
              <tr>
              <?php foreach ($row as $val): ?>
                <td title="<?= htmlspecialchars((string)$val, ENT_QUOTES, 'UTF-8') ?>">
                  <?php if ($val === null): ?>
                    <span class="null">NULL</span>
                  <?php else:
                    $htype = detectHashType((string)$val);
                    if ($htype): ?>
                      <span class="hash-cell">
                        <span class="hash-tag <?= hashStrength($htype) ?>"><?= htmlspecialchars($htype, ENT_QUOTES, 'UTF-8') ?></span>
                        <?= htmlspecialchars((string)$val, ENT_QUOTES, 'UTF-8') ?>
                      </span>
                    <?php else: ?>
                      <?= htmlspecialchars((string)$val, ENT_QUOTES, 'UTF-8') ?>
                    <?php endif; ?>
                  <?php endif; ?>
                </td>
              <?php endforeach; ?>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
      <?php endif; ?>

    </div><!-- /sql-editor-wrap -->
  </form>
</div>

<script>
// Ctrl+Enter submit
(function(){
  var ta = document.getElementById('sql-inp');
  if (!ta) return;
  ta.addEventListener('keydown', function(e){
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      ta.closest('form').querySelector('[name=sql_exec]').click();
    }
  });
})();

// History fill
var _hist = <?= json_encode($history) ?>;
function fillSql(i) {
  var ta = document.getElementById('sql-inp');
  if (ta && _hist[i] !== undefined) { ta.value = _hist[i]; ta.focus(); }
}
</script>

<?php
    return ob_get_clean();
}
?>

</body>
</html>
