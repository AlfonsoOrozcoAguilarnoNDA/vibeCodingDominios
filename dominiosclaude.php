<?php
/**
 * ============================================================================
 * Sistema de Control de Dominios
 * ============================================================================
 * AUTOR:         vibecodingmexico.com
 * MODELO:        Claude Sonnet 4.6 (claude-sonnet-4-6)
 * FECHA:         14 de marzo de 2026
 * LICENCIA:      MIT
 * STACK:         PHP 8.x Procedural, Bootstrap 4.6, Font Awesome 5
 * NOTA:          Asume config.php con $link (mysqli)
 *
 * CREATE TABLE `dominios2020` (
 *   `dominio` varchar(65) NOT NULL,
 *   `servidores` varchar(250) NOT NULL,
 *   `registered` date DEFAULT NULL,
 *   `expiration` date DEFAULT NULL,
 *   `registrar` varchar(50) DEFAULT NULL,
 *   `showit` varchar(3) DEFAULT 'YES',
 *   `iscustomer` varchar(3) NOT NULL DEFAULT 'NO',
 *   `type` varchar(25) NOT NULL,
 *   `NOTA` varchar(2000) DEFAULT NULL,
 *   `last_updated` date DEFAULT NULL,
 *   PRIMARY KEY (`dominio`)
 * ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
 */

// Headers anti-caché
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');
header('Content-Type: text/html; charset=UTF-8');

session_start();
include_once 'config.php';
global $link;

// ============================================================
// CONSTANTES Y CONFIGURACIÓN
// ============================================================
define('EXTENSIONES_MX', ['.mx', '.com.mx']);
define('EXTENSIONES_GENERALES', ['.com', '.net', '.org', '.info', '.monster', '.xyz', '.vip', '.mom']);
define('DIAS_ROJO',    14);
define('DIAS_AMARILLO', 60);
define('DIAS_VERDE',   370);

// ============================================================
// FUNCIONES AUXILIARES
// ============================================================

function limpiar($val) {
    return htmlspecialchars($val ?? '', ENT_QUOTES, 'UTF-8');
}

function obtener_extension($dominio) {
    // Detectar .com.mx primero (doble extensión)
    if (substr($dominio, -7) === '.com.mx') return '.com.mx';
    $pos = strrpos($dominio, '.');
    return $pos !== false ? substr($dominio, $pos) : '';
}

function es_dominio_mx($dominio) {
    return in_array(obtener_extension($dominio), EXTENSIONES_MX);
}

function clase_fila($expiration) {
    if (empty($expiration) || $expiration === '0000-00-00') return '';
    $hoy  = new DateTime();
    $exp  = new DateTime($expiration);
    $dias = (int)$hoy->diff($exp)->days;
    $pasado = $exp < $hoy;
    if ($pasado)                     return 'fila-vencida';
    if ($dias <= DIAS_ROJO)          return 'fila-roja';
    if ($dias <= DIAS_AMARILLO)      return 'fila-amarilla';
    if ($dias >= DIAS_VERDE)         return 'fila-verde';
    return '';
}

function dias_restantes($expiration) {
    if (empty($expiration) || $expiration === '0000-00-00') return '—';
    $hoy  = new DateTime();
    $exp  = new DateTime($expiration);
    $dias = (int)$hoy->diff($exp)->days;
    if ($exp < $hoy) return '<span class="badge badge-dark">Vencido</span>';
    if ($dias <= DIAS_ROJO)     return '<span class="badge badge-danger">' . $dias . ' días</span>';
    if ($dias <= DIAS_AMARILLO) return '<span class="badge badge-warning text-dark">' . $dias . ' días</span>';
    if ($dias >= DIAS_VERDE)    return '<span class="badge badge-success">' . $dias . ' días</span>';
    return '<span class="badge badge-secondary">' . $dias . ' días</span>';
}

// ============================================================
// WHOIS — FUNCIÓN GENERAL (.com .net .org etc.)
// ============================================================
function whois_general($dominio) {
    $ext      = obtener_extension($dominio);
    $servidores_whois = [
        '.com'     => 'whois.verisign-grs.com',
        '.net'     => 'whois.verisign-grs.com',
        '.org'     => 'whois.pir.org',
        '.info'    => 'whois.afilias.net',
        '.monster' => 'whois.nic.monster',
        '.xyz'     => 'whois.nic.xyz',
        '.vip'     => 'whois.nic.vip',
        '.mom'     => 'whois.nic.mom',
    ];

    $servidor = $servidores_whois[$ext] ?? null;
    if (!$servidor) return null;

    $resultado = consultar_whois_socket($servidor, $dominio);
    return parsear_whois_general($resultado);
}

// ============================================================
// WHOIS — FUNCIÓN ESPECIAL .mx y .com.mx
// ============================================================
function whois_mx($dominio) {
    // NIC México usa whois.mx
    $resultado = consultar_whois_socket('whois.mx', $dominio);
    return parsear_whois_mx($resultado);
}

// ============================================================
// WHOIS — CONSULTA POR SOCKET
// ============================================================
function consultar_whois_socket($servidor, $dominio) {
    $sock = @fsockopen($servidor, 43, $errno, $errstr, 10);
    if (!$sock) return '';
    fwrite($sock, $dominio . "\r\n");
    $respuesta = '';
    while (!feof($sock)) {
        $respuesta .= fread($sock, 4096);
    }
    fclose($sock);
    return $respuesta;
}

// ============================================================
// PARSEAR WHOIS GENERAL
// ============================================================
function parsear_whois_general($raw) {
    $datos = [
        'expiration' => null,
        'registered' => null,
        'registrar'  => null,
        'servidores' => null,
    ];
    if (empty($raw)) return $datos;

    $lineas = explode("\n", $raw);
    $ns = [];

    foreach ($lineas as $linea) {
        $linea = trim($linea);
        $lower = strtolower($linea);

        // Fecha expiración
        if ($datos['expiration'] === null && (
            str_starts_with($lower, 'registry expiry date:') ||
            str_starts_with($lower, 'expiration date:') ||
            str_starts_with($lower, 'expires on:') ||
            str_starts_with($lower, 'paid-till:') ||
            str_starts_with($lower, 'expiry date:')
        )) {
            $val = trim(substr($linea, strpos($linea, ':') + 1));
            $datos['expiration'] = parsear_fecha_whois($val);
        }

        // Fecha registro
        if ($datos['registered'] === null && (
            str_starts_with($lower, 'creation date:') ||
            str_starts_with($lower, 'created on:') ||
            str_starts_with($lower, 'registered on:')
        )) {
            $val = trim(substr($linea, strpos($linea, ':') + 1));
            $datos['registered'] = parsear_fecha_whois($val);
        }

        // Registrar
        if ($datos['registrar'] === null && str_starts_with($lower, 'registrar:')) {
            $datos['registrar'] = trim(substr($linea, strpos($linea, ':') + 1));
        }

        // Name servers
        if (str_starts_with($lower, 'name server:') || str_starts_with($lower, 'nserver:')) {
            $ns[] = strtolower(trim(substr($linea, strpos($linea, ':') + 1)));
        }
    }

    if (!empty($ns)) $datos['servidores'] = implode(', ', array_unique($ns));
    return $datos;
}

// ============================================================
// PARSEAR WHOIS .MX
// ============================================================
function parsear_whois_mx($raw) {
    $datos = [
        'expiration' => null,
        'registered' => null,
        'registrar'  => null,
        'servidores' => null,
    ];
    if (empty($raw)) return $datos;

    $lineas = explode("\n", $raw);
    $ns = [];

    foreach ($lineas as $linea) {
        $linea = trim($linea);
        $lower = strtolower($linea);

        if ($datos['expiration'] === null && str_starts_with($lower, 'expiration date:')) {
            $val = trim(substr($linea, strpos($linea, ':') + 1));
            $datos['expiration'] = parsear_fecha_whois($val);
        }
        if ($datos['registered'] === null && str_starts_with($lower, 'created on:')) {
            $val = trim(substr($linea, strpos($linea, ':') + 1));
            $datos['registered'] = parsear_fecha_whois($val);
        }
        if ($datos['registrar'] === null && str_starts_with($lower, 'registrar:')) {
            $datos['registrar'] = trim(substr($linea, strpos($linea, ':') + 1));
        }
        if (str_starts_with($lower, 'dns:') || str_starts_with($lower, 'name server:')) {
            $ns[] = strtolower(trim(substr($linea, strpos($linea, ':') + 1)));
        }
    }

    if (!empty($ns)) $datos['servidores'] = implode(', ', array_unique($ns));
    return $datos;
}

// ============================================================
// PARSEAR FECHA WHOIS (varios formatos)
// ============================================================
function parsear_fecha_whois($str) {
    $str = trim($str);
    // Quitar zona horaria tipo "2027-03-10T00:00:00Z"
    $str = preg_replace('/T.*$/', '', $str);
    $str = preg_replace('/\s+.*$/', '', $str);

    $formatos = ['Y-m-d', 'd-M-Y', 'Y/m/d', 'd/m/Y', 'Ymd'];
    foreach ($formatos as $fmt) {
        $d = DateTime::createFromFormat($fmt, $str);
        if ($d) return $d->format('Y-m-d');
    }
    return null;
}

// ============================================================
// ACCIÓN: ACTUALIZAR WHOIS
// ============================================================
$accion  = $_GET['accion'] ?? '';
$mensaje = '';
$error   = '';

if ($accion === 'whois' && isset($_GET['dominio'])) {
    $dominio = trim($_GET['dominio']);

    $datos = es_dominio_mx($dominio)
        ? whois_mx($dominio)
        : whois_general($dominio);

    if ($datos && array_filter($datos)) {
        $campos = [];
        $params = [];
        $types  = '';

        if (!empty($datos['expiration'])) { $campos[] = 'expiration = ?';  $params[] = $datos['expiration']; $types .= 's'; }
        if (!empty($datos['registered'])) { $campos[] = 'registered = ?';  $params[] = $datos['registered']; $types .= 's'; }
        if (!empty($datos['registrar']))  { $campos[] = 'registrar = ?';   $params[] = $datos['registrar'];  $types .= 's'; }
        if (!empty($datos['servidores'])) { $campos[] = 'servidores = ?';  $params[] = $datos['servidores']; $types .= 's'; }
        $campos[]  = 'last_updated = ?';
        $params[]  = date('Y-m-d');
        $types    .= 's';
        $params[]  = $dominio;
        $types    .= 's';

        $sql  = "UPDATE dominios2020 SET " . implode(', ', $campos) . " WHERE dominio = ?";
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, $types, ...$params);
        if (mysqli_stmt_execute($stmt)) {
            $mensaje = "WHOIS actualizado para: $dominio";
        } else {
            $error = "Error al actualizar: " . mysqli_error($link);
        }
    } else {
        $error = "No se pudo obtener datos WHOIS para: $dominio";
    }
}

// ============================================================
// FILTROS
// ============================================================
$f_ext        = $_GET['f_ext']        ?? '';
$f_type       = $_GET['f_type']       ?? '';
$f_iscustomer = $_GET['f_iscustomer'] ?? '';
$f_registrar  = $_GET['f_registrar']  ?? '';

$where  = "WHERE showit = 'YES'";
$params = [];
$types  = '';

if ($f_ext) {
    if ($f_ext === '.com.mx') {
        $where .= " AND dominio LIKE ?";
        $params[] = '%.com.mx';
        $types   .= 's';
    } elseif ($f_ext === '.mx') {
        $where .= " AND dominio LIKE ? AND dominio NOT LIKE ?";
        $params[] = '%.mx';
        $params[] = '%.com.mx';
        $types   .= 'ss';
    } else {
        $where .= " AND dominio LIKE ?";
        $params[] = '%' . $f_ext;
        $types   .= 's';
    }
}
if ($f_type)       { $where .= " AND type = ?";        $params[] = $f_type;       $types .= 's'; }
if ($f_iscustomer) { $where .= " AND iscustomer = ?";  $params[] = $f_iscustomer; $types .= 's'; }
if ($f_registrar)  { $where .= " AND registrar LIKE ?"; $params[] = "%$f_registrar%"; $types .= 's'; }

$sql  = "SELECT * FROM dominios2020 $where ORDER BY expiration ASC";
$stmt = mysqli_prepare($link, $sql);
if (!empty($types)) mysqli_stmt_bind_param($stmt, $types, ...$params);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

// Obtener registrars y types únicos para filtros
$registrars = [];
$types_list = [];
$res_r = mysqli_query($link, "SELECT DISTINCT registrar FROM dominios2020 WHERE registrar IS NOT NULL AND registrar != '' ORDER BY registrar");
while ($r = mysqli_fetch_assoc($res_r)) $registrars[] = $r['registrar'];
$res_t = mysqli_query($link, "SELECT DISTINCT type FROM dominios2020 WHERE type != '' ORDER BY type");
while ($r = mysqli_fetch_assoc($res_t)) $types_list[] = $r['type'];

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Control de Dominios</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@5.15.4/css/all.min.css">
    <style>
        :root {
            --nav-bg: linear-gradient(135deg, #2c3e50, #34495e);
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, sans-serif;
            background-color: #f0f2f5;
            padding-top: 70px;
            padding-bottom: 70px;
        }
        .navbar {
            background: var(--nav-bg) !important;
            box-shadow: 0 2px 10px rgba(0,0,0,.3);
        }
        .navbar-brand { font-weight: 700; }
        .card-metro {
            background: #fff;
            border-radius: 15px;
            box-shadow: 0 8px 25px rgba(0,0,0,.1);
            overflow: hidden;
            border: none;
            margin-bottom: 1.5rem;
        }
        .card-header-metro {
            background: var(--nav-bg);
            color: #fff;
            padding: 12px 20px;
        }
        .table thead th {
            background: var(--nav-bg);
            color: #fff;
            border: none;
            font-size: .85rem;
        }
        .table td { vertical-align: middle; font-size: .88rem; }

        /* Colores de filas */
        .fila-roja     { background-color: #fde8e8 !important; }
        .fila-amarilla { background-color: #fef9e7 !important; }
        .fila-verde    { background-color: #eafaf1 !important; }
        .fila-vencida  { background-color: #f2f2f2 !important; color: #999; }

        .filter-card {
            background: #fff;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,.08);
            padding: 20px 24px;
            margin-bottom: 1.5rem;
        }

        /* Footer fijo */
        footer.footer-fixed {
            background: var(--nav-bg);
            color: rgba(255,255,255,.85);
            position: fixed;
            bottom: 0;
            width: 100%;
            z-index: 1030;
            padding: 7px 0;
            font-size: .78rem;
            text-align: center;
        }

        .leyenda-colores span {
            display: inline-block;
            width: 14px; height: 14px;
            border-radius: 3px;
            margin-right: 4px;
            vertical-align: middle;
        }
        .btn-whois {
            background: linear-gradient(135deg, #2980b9, #3498db);
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 3px 8px;
            font-size: .8rem;
            transition: all .2s;
        }
        .btn-whois:hover { transform: translateY(-1px); color: #fff; box-shadow: 0 3px 8px rgba(0,0,0,.2); }
        .dominio-link { font-weight: 600; color: #2c3e50; }
        .dominio-link:hover { color: #3498db; }
    </style>
</head>
<body>

<!-- NAVBAR -->
<nav class="navbar navbar-expand-lg navbar-dark fixed-top">
    <div class="container-fluid">
        <a class="navbar-brand" href="?">
            <i class="fas fa-globe mr-2"></i>Control de Dominios
        </a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item">
                    <a class="nav-link" href="https://google.com" target="_blank">
                        <i class="fab fa-google mr-1"></i>Google
                    </a>
                </li>
            </ul>
            <span class="navbar-text text-white-50 small">
                <i class="fas fa-robot mr-1"></i>Claude Sonnet 4.6 (claude-sonnet-4-6)
            </span>
        </div>
    </div>
</nav>

<div class="container-fluid px-4">

    <?php if ($mensaje): ?>
    <div class="alert alert-success alert-dismissible fade show mt-3">
        <i class="fas fa-check-circle mr-2"></i><?php echo limpiar($mensaje); ?>
        <button type="button" class="close" data-dismiss="alert">&times;</button>
    </div>
    <?php endif; ?>

    <?php if ($error): ?>
    <div class="alert alert-danger alert-dismissible fade show mt-3">
        <i class="fas fa-exclamation-circle mr-2"></i><?php echo limpiar($error); ?>
        <button type="button" class="close" data-dismiss="alert">&times;</button>
    </div>
    <?php endif; ?>

    <!-- FILTROS -->
    <div class="filter-card mt-3">
        <h6 class="mb-3"><i class="fas fa-filter mr-2"></i>Filtros</h6>
        <form method="get" class="form-row align-items-end">
            <div class="col-md-2 mb-2">
                <label class="small">Extensión</label>
                <select name="f_ext" class="form-control form-control-sm">
                    <option value="">Todas</option>
                    <?php foreach (array_merge(EXTENSIONES_GENERALES, EXTENSIONES_MX) as $ext): ?>
                    <option value="<?php echo $ext; ?>" <?php echo $f_ext===$ext?'selected':''; ?>><?php echo $ext; ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-2 mb-2">
                <label class="small">Tipo</label>
                <select name="f_type" class="form-control form-control-sm">
                    <option value="">Todos</option>
                    <?php foreach ($types_list as $t): ?>
                    <option value="<?php echo limpiar($t); ?>" <?php echo $f_type===$t?'selected':''; ?>><?php echo limpiar($t); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-2 mb-2">
                <label class="small">¿Cliente?</label>
                <select name="f_iscustomer" class="form-control form-control-sm">
                    <option value="">Todos</option>
                    <option value="YES" <?php echo $f_iscustomer==='YES'?'selected':''; ?>>Sí</option>
                    <option value="NO"  <?php echo $f_iscustomer==='NO' ?'selected':''; ?>>No</option>
                </select>
            </div>
            <div class="col-md-3 mb-2">
                <label class="small">Registrar</label>
                <select name="f_registrar" class="form-control form-control-sm">
                    <option value="">Todos</option>
                    <?php foreach ($registrars as $reg): ?>
                    <option value="<?php echo limpiar($reg); ?>" <?php echo $f_registrar===$reg?'selected':''; ?>><?php echo limpiar($reg); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-3 mb-2">
                <button type="submit" class="btn btn-sm btn-primary mr-2">
                    <i class="fas fa-search mr-1"></i>Filtrar
                </button>
                <a href="?" class="btn btn-sm btn-outline-secondary">
                    <i class="fas fa-times mr-1"></i>Limpiar
                </a>
            </div>
        </form>

        <!-- Leyenda -->
        <div class="leyenda-colores mt-2 small text-muted">
            <span style="background:#e74c3c;"></span>Vence en menos de <?php echo DIAS_ROJO; ?> días &nbsp;
            <span style="background:#f1c40f;"></span>Menos de <?php echo DIAS_AMARILLO; ?> días &nbsp;
            <span style="background:#27ae60;"></span>Más de <?php echo DIAS_VERDE; ?> días &nbsp;
            <span style="background:#bbb;"></span>Vencido
        </div>
    </div>

    <!-- TABLA -->
    <div class="card-metro">
        <div class="card-header-metro d-flex justify-content-between align-items-center">
            <h6 class="mb-0"><i class="fas fa-list mr-2"></i>Dominios — ordenados por expiración</h6>
            <small><?php echo mysqli_num_rows($result); ?> registro(s)</small>
        </div>
        <div class="table-responsive">
            <table class="table table-hover mb-0">
                <thead>
                    <tr>
                        <th>Dominio</th>
                        <th>Extensión</th>
                        <th>Registrar</th>
                        <th>Name Servers</th>
                        <th>Registrado</th>
                        <th>Expira</th>
                        <th>Días</th>
                        <th>Tipo</th>
                        <th>Cliente</th>
                        <th>Actualizado</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                <?php
                $total = 0;
                while ($row = mysqli_fetch_assoc($result)):
                    $total++;
                    $cls = clase_fila($row['expiration']);
                    $ext = obtener_extension($row['dominio']);
                ?>
                <tr class="<?php echo $cls; ?>">
                    <td>
                        <a href="http://<?php echo limpiar($row['dominio']); ?>" 
                           target="_blank" class="dominio-link">
                            <i class="fas fa-external-link-alt mr-1 small"></i><?php echo limpiar($row['dominio']); ?>
                        </a>
                        <?php if (!empty($row['NOTA'])): ?>
                        <br><small class="text-muted"><?php echo limpiar(substr($row['NOTA'], 0, 60)); ?><?php echo strlen($row['NOTA'])>60?'...':''; ?></small>
                        <?php endif; ?>
                    </td>
                    <td><span class="badge badge-info"><?php echo limpiar($ext); ?></span></td>
                    <td><small><?php echo limpiar($row['registrar'] ?? '—'); ?></small></td>
                    <td><small style="font-size:.75rem;"><?php echo limpiar($row['servidores'] ?? '—'); ?></small></td>
                    <td><small><?php echo $row['registered'] ?? '—'; ?></small></td>
                    <td><small><?php echo $row['expiration'] ?? '—'; ?></small></td>
                    <td><?php echo dias_restantes($row['expiration']); ?></td>
                    <td><small><?php echo limpiar($row['type']); ?></small></td>
                    <td>
                        <?php if ($row['iscustomer'] === 'YES'): ?>
                        <span class="badge badge-success">Sí</span>
                        <?php else: ?>
                        <span class="badge badge-secondary">No</span>
                        <?php endif; ?>
                    </td>
                    <td><small><?php echo $row['last_updated'] ?? '—'; ?></small></td>
                    <td>
                        <a href="?accion=whois&dominio=<?php echo urlencode($row['dominio']); ?>&<?php echo http_build_query($_GET); ?>"
                           class="btn-whois" title="Actualizar WHOIS">
                            <i class="fas fa-sync-alt mr-1"></i>WHOIS
                        </a>
                    </td>
                </tr>
                <?php endwhile; ?>
                <?php if ($total === 0): ?>
                <tr>
                    <td colspan="11" class="text-center text-muted py-4">
                        <i class="fas fa-inbox fa-2x d-block mb-2"></i>No se encontraron dominios
                    </td>
                </tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

</div>

<!-- FOOTER FIJO -->
<footer class="footer-fixed">
    <i class="fas fa-globe mr-1"></i>Control de Dominios &nbsp;|&nbsp;
    <i class="fas fa-code mr-1"></i>PHP <?php echo phpversion(); ?> &nbsp;|&nbsp;
    <i class="fas fa-robot mr-1"></i>Claude Sonnet 4.6 &nbsp;|&nbsp;
    <i class="fas fa-calendar mr-1"></i><?php echo date('Y-m-d H:i'); ?>
</footer>

<script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php mysqli_close($link); ?>