<?php
/**
 * dominios.php - Control de Dominios y expirationes
 * 
 * Modelo de IA: Together Chat (MiniMax-M2.5)
 * Fecha: 13 de marzo de 2026
 * Co-programador en el experimento vibecodingmexico.com
 * 
 * Stack: PHP 8.x Procedural, Bootstrap 4.6, Font Awesome 5.0
 */

// Headers de caché
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

session_start();

// Incluir config.php
include_once 'config.php';

global $link;

// ============================================
// FUNCIONES WHOIS
// ============================================

/**
 * Obtiene información WHOIS de un dominio (extensiones estándar)
 * .com, .net, .org, .info, .monster, .xyz, .vip, .mom
 */
function whois_dominio($dominio) {
    $ext = strtolower(pathinfo($dominio, PATHINFO_EXTENSION));
    
    // Servidores WHOIS por extensión
    $whois_servers = [
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'org' => 'whois.pir.org',
        'info' => 'whois.afilias.info',
        'monster' => 'whois.centralreg.com',
        'xyz' => 'whois.nic.xyz',
        'vip' => 'whois.nic.vip',
        'mom' => 'whois.nic.mom'
    ];
    
    if (!isset($whois_servers[$ext])) {
        return ['error' => 'Extensión no soportada: ' . $ext];
    }
    
    $server = $whois_servers[$ext];
    $port = 43;
    $timeout = 10;
    
    $fp = @fsockopen($server, $port, $errno, $errstr, $timeout);
    if (!$fp) {
        return ['error' => 'No se puede conectar al servidor WHOIS'];
    }
    
    stream_set_timeout($fp, $timeout);
    fwrite($fp, $dominio . "\r\n");
    
    $response = '';
    while (!feof($fp)) {
        $response .= fgets($fp, 4096);
    }
    fclose($fp);
    
    return parse_whois_response($response, $ext);
}

/**
 * Obtiene información WHOIS de dominios .mx y .com.mx
 * Utiliza la API de NIC México
 */
function whois_dominio_mx($dominio) {
    $ext = strtolower(pathinfo($dominio, PATHINFO_EXTENSION));
    
    if (!in_array($ext, ['mx', 'com.mx'])) {
        return ['error' => 'Extensión no válida para función MX'];
    }
    
    // Usar socket conexión directa al whois de NIC México
    $server = 'whois.nic.mx';
    $port = 43;
    $timeout = 10;
    
    $fp = @fsockopen($server, $port, $errno, $errstr, $timeout);
    if (!$fp) {
        return ['error' => 'No se puede conectar al servidor WHOIS de México'];
    }
    
    stream_set_timeout($fp, $timeout);
    fwrite($fp, $dominio . "\r\n");
    
    $response = '';
    while (!feof($fp)) {
        $response .= fgets($fp, 4096);
    }
    fclose($fp);
    
    return parse_whois_mx($response);
}

/**
 * Parsea la respuesta WHOIS estándar
 */
function parse_whois_response($response, $ext) {
    $result = [
        'registrar' => '',
        'creation_date' => null,
        'expiration_date' => null,
        'name_servers' => []
    ];
    
    $lines = explode("\n", $response);
    
    foreach ($lines as $line) {
        $line = trim($line);
        
        // Buscar Registrar
        if (stripos($line, 'Registrar:') !== false) {
            $result['registrar'] = trim(substr($line, strpos($line, ':') + 1));
        }
        
        // Buscar Creation Date
        if (stripos($line, 'Creation Date:') !== false || stripos($line, 'Created:') !== false) {
            $date = trim(substr($line, strpos($line, ':') + 1));
            $result['creation_date'] = parse_date($date);
        }
        
        // Buscar Expiration Date
        if (stripos($line, 'Expiration Date:') !== false || stripos($line, 'Expires:') !== false) {
            $date = trim(substr($line, strpos($line, ':') + 1));
            $result['expiration_date'] = parse_date($date);
        }
        
        // Buscar Name Servers
        if (stripos($line, 'Name Server:') !== false || stripos($line, 'Name servers:') !== false) {
            $ns = trim(substr($line, strpos($line, ':') + 1));
            if (!empty($ns)) {
                $result['name_servers'][] = $ns;
            }
        }
    }
    
    return $result;
}

/**
 * Parsea la respuesta WHOIS de dominios .mx
 */
function parse_whois_mx($response) {
    $result = [
        'registrar' => '',
        'creation_date' => null,
        'expiration_date' => null,
        'name_servers' => []
    ];
    
    $lines = explode("\n", $response);
    
    foreach ($lines as $line) {
        $line = trim($line);
        
        // Buscar Registrar
        if (stripos($line, 'Registrar:') !== false) {
            $result['registrar'] = trim(substr($line, strpos($line, ':') + 1));
        }
        
        // Buscar Created Date
        if (stripos($line, 'Created:') !== false) {
            $date = trim(substr($line, strpos($line, ':') + 1));
            $result['creation_date'] = parse_date($date);
        }
        
        // Buscar Expiration Date
        if (stripos($line, 'Expiration:') !== false) {
            $date = trim(substr($line, strpos($line, ':') + 1));
            $result['expiration_date'] = parse_date($date);
        }
        
        // Buscar Name Servers
        if (stripos($line, 'Name Server:') !== false || stripos($line, 'NS:') !== false) {
            $ns = trim(substr($line, strpos($line, ':') + 1));
            if (!empty($ns) && strpos($ns, '.') !== false) {
                $result['name_servers'][] = $ns;
            }
        }
    }
    
    return $result;
}

/**
 * Convierte diferentes formatos de fecha a formato YYYY-MM-DD
 */
function parse_date($date_str) {
    $date_str = trim($date_str);
    
    // Intentar varios formatos
    $formats = ['Y-m-d', 'd-M-Y', 'Y-m-d H:i:s', 'Y/m/d'];
    
    foreach ($formats as $format) {
        $date = DateTime::createFromFormat($format, $date_str);
        if ($date !== false) {
            return $date->format('Y-m-d');
        }
    }
    
    // Si es timestamp Unix
    if (is_numeric($date_str)) {
        return date('Y-m-d', $date_str);
    }
    
    return null;
}

/**
 * Actualiza la información de un dominio en la base de datos
 */
function actualizar_dominio($link, $dominio) {
    $ext = strtolower(pathinfo($dominio, PATHINFO_EXTENSION));
    
    // Elegir función WHOIS según extensión
    if (in_array($ext, ['mx', 'com.mx'])) {
        $whois = whois_dominio_mx($dominio);
    } else {
        $whois = whois_dominio($dominio);
    }
    
    if (isset($whois['error'])) {
        return ['success' => false, 'message' => $whois['error']];
    }
    
    $servidores = !empty($whois['name_servers']) ? implode(', ', $whois['name_servers']) : '';
    $registered = $whois['creation_date'] ?? null;
    $expiration = $whois['expiration_date'] ?? null;
    $registrar = $whois['registrar'] ?? 'Unknown';
    $today = date('Y-m-d');
    
    $sql = "UPDATE dominios2020 SET servidores = ?, registered = ?, expiration = ?, registrar = ?, last_updated = ? WHERE dominio = ?";
    $stmt = mysqli_prepare($link, $sql);
    mysqli_stmt_bind_param($stmt, 'ssssss', $servidores, $registered, $expiration, $registrar, $today, $dominio);
    
    if (mysqli_stmt_execute($stmt)) {
        return ['success' => true, 'message' => 'Actualizado correctamente'];
    } else {
        return ['success' => false, 'message' => 'Error al actualizar: ' . mysqli_error($link)];
    }
}

/**
 * Calcula los días hasta la expiración y el color correspondiente
 */
function get_dias_expiracion($expiration) {
    if (empty($expiration) || $expiration === '0000-00-00') {
        return ['dias' => null, 'color' => ''];
    }
    
    $exp_date = new DateTime($expiration);
    $today = new DateTime(date('Y-m-d'));
    $diff = $today->diff($exp_date);
    
    $dias = $diff->days;
    if ($exp_date < $today) {
        $dias = -$dias; // Ya expiró
    }
    
    // Determinar color
    if ($dias < 0) {
        $color = 'expired'; // Ya expiró
    } elseif ($dias < 14) {
        $color = 'danger'; // Rojo: menos de 14 días
    } elseif ($dias < 60) {
        $color = 'warning'; // Amarillo: menos de 60 días
    } elseif ($dias > 370) {
        $color = 'success'; // Verde: más de 370 días
    } else {
        $color = 'normal'; // Blanco: resto
    }
    
    return ['dias' => $dias, 'color' => $color];
}

// ============================================
// VARIABLES DE CONTROL
// ============================================
$accion = $_GET['accion'] ?? 'listado';
$mensaje = '';
$tipo_mensaje = '';

// Filtros
$f_ext = $_GET['f_ext'] ?? '';
$f_type = $_GET['f_type'] ?? '';
$f_iscustomer = $_GET['f_iscustomer'] ?? '';
$f_registrar = $_GET['f_registrar'] ?? '';
$busqueda = $_GET['busqueda'] ?? '';

// ============================================
// PROCESAMIENTO DE ACCIONES
// ============================================

// Actualizar dominio específico
if ($accion === 'actualizar' && isset($_GET['dominio'])) {
    $dominio = $_GET['dominio'];
    $resultado = actualizar_dominio($link, $dominio);
    
    if ($resultado['success']) {
        $mensaje = 'Dominio ' . $dominio . ' actualizado: ' . $resultado['message'];
        $tipo_mensaje = 'success';
    } else {
        $mensaje = 'Error: ' . $resultado['message'];
        $tipo_mensaje = 'danger';
    }
    $accion = 'listado';
}

// Agregar nuevo dominio
if ($accion === 'agregar' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $dominio = strtolower(trim($_POST['dominio'] ?? ''));
    $type = $_POST['type'] ?? 'CLIENTE';
    $iscustomer = $_POST['iscustomer'] ?? 'NO';
    $NOTA = $_POST['NOTA'] ?? '';
    
    if (empty($dominio)) {
        $mensaje = 'El dominio es obligatorio';
        $tipo_mensaje = 'danger';
    } else {
        // Intentar obtener WHOIS inicial
        $whois = whois_dominio($dominio);
        
        $servidores = !empty($whois['name_servers']) ? implode(', ', $whois['name_servers']) : '';
        $registered = $whois['creation_date'] ?? null;
        $expiration = $whois['expiration_date'] ?? null;
        $registrar = $whois['registrar'] ?? 'Unknown';
        $today = date('Y-m-d');
        
        $sql = "INSERT INTO dominios2020 (dominio, servidores, registered, expiration, registrar, type, iscustomer, NOTA, last_updated, showit) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'YES')";
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, 'sssssssss', $dominio, $servidores, $registered, $expiration, $registrar, $type, $iscustomer, $NOTA, $today);
        
        if (mysqli_stmt_execute($stmt)) {
            $mensaje = 'Dominio ' . $dominio . ' agregado correctamente';
            $tipo_mensaje = 'success';
        } else {
            $mensaje = 'Error al agregar: ' . mysqli_error($link);
            $tipo_mensaje = 'danger';
        }
    }
    $accion = 'listado';
}

// Editar dominio
if ($accion === 'editar' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $dominio_original = $_POST['dominio_original'] ?? '';
    $dominio = strtolower(trim($_POST['dominio'] ?? ''));
    $type = $_POST['type'] ?? 'CLIENTE';
    $iscustomer = $_POST['iscustomer'] ?? 'NO';
    $NOTA = $_POST['NOTA'] ?? '';
    $showit = $_POST['showit'] ?? 'YES';
    
    if (empty($dominio)) {
        $mensaje = 'El dominio es obligatorio';
        $tipo_mensaje = 'danger';
    } else {
        $sql = "UPDATE dominios2020 SET dominio = ?, type = ?, iscustomer = ?, NOTA = ?, showit = ? WHERE dominio = ?";
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, 'ssssss', $dominio, $type, $iscustomer, $NOTA, $showit, $dominio_original);
        
        if (mysqli_stmt_execute($stmt)) {
            $mensaje = 'Dominio actualizado correctamente';
            $tipo_mensaje = 'success';
        } else {
            $mensaje = 'Error al actualizar: ' . mysqli_error($link);
            $tipo_mensaje = 'danger';
        }
    }
    $accion = 'listado';
}

// Eliminar dominio
if ($accion === 'eliminar' && isset($_GET['dominio'])) {
    $dominio = $_GET['dominio'];
    
    $sql = "DELETE FROM dominios2020 WHERE dominio = ?";
    $stmt = mysqli_prepare($link, $sql);
    mysqli_stmt_bind_param($stmt, 's', $dominio);
    
    if (mysqli_stmt_execute($stmt)) {
        $mensaje = 'Dominio ' . $dominio . ' eliminado';
        $tipo_mensaje = 'success';
    } else {
        $mensaje = 'Error al eliminar';
        $tipo_mensaje = 'danger';
    }
    $accion = 'listado';
}

// ============================================
// CONSULTAS
// ============================================

// Obtener lista de registrars para filtro
$sql_registrars = "SELECT DISTINCT registrar FROM dominios2020 ORDER BY registrar";
$result_registrars = mysqli_query($link, $sql_registrars);
$registrars = [];
while ($row = mysqli_fetch_assoc($result_registrars)) {
    $registrars[] = $row['registrar'];
}

// Construir consulta con filtros
$where = " WHERE showit = 'YES'";
$params = [];
$types = '';

if (!empty($f_ext)) {
    $where .= " AND dominio LIKE ?";
    $params[] = '%.' . $f_ext;
    $types .= 's';
}

if (!empty($f_type)) {
    $where .= " AND type = ?";
    $params[] = $f_type;
    $types .= 's';
}

if (!empty($f_iscustomer)) {
    $where .= " AND iscustomer = ?";
    $params[] = $f_iscustomer;
    $types .= 's';
}

if (!empty($f_registrar)) {
    $where .= " AND registrar = ?";
    $params[] = $f_registrar;
    $types .= 's';
}

if (!empty($busqueda)) {
    $where .= " AND (dominio LIKE ? OR NOTA LIKE ?)";
    $busqueda_like = "%$busqueda%";
    $params[] = $busqueda_like;
    $params[] = $busqueda_like;
    $types .= 'ss';
}

// Ordenar por expiracion (mas pronto primero)
$sql = "SELECT * FROM dominios2020" . $where . " ORDER BY expiration ASC";
$stmt = mysqli_prepare($link, $sql);
if (!empty($types)) {
    mysqli_stmt_bind_param($stmt, $types, ...$params);
}
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

$dominios = [];
while ($row = mysqli_fetch_assoc($result)) {
    $row['dias_info'] = get_dias_expiracion($row['expiration']);
    $dominios[] = $row;
}

// Obtener dominio para editar
$dominio_editar = null;
if ($accion === 'editar' && isset($_GET['dominio'])) {
    $stmt = mysqli_prepare($link, "SELECT * FROM dominios2020 WHERE dominio = ?");
    mysqli_stmt_bind_param($stmt, 's', $_GET['dominio']);
    mysqli_stmt_execute($stmt);
    $result_editar = mysqli_stmt_get_result($stmt);
    $dominio_editar = mysqli_fetch_assoc($result_editar);
}

// Extensions válidas
$extensiones_validas = ['com', 'net', 'org', 'info', 'monster', 'xyz', 'vip', 'mom', 'mx', 'com.mx'];

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Control de Dominios - Lemkotir</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        :root {
            --metro-blue: #3498db;
            --metro-green: #27ae60;
            --metro-red: #e74c3c;
            --metro-orange: #e67e22;
            --metro-purple: #9b59b6;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, sans-serif;
            background: linear-gradient(135deg, #1a2a6c 0%, #2c3e50 50%, #4a69bd 100%);
            min-height: 100vh;
            margin: 0;
            padding: 0;
        }
        
        .main-container {
            padding-top: 90px;
            padding-bottom: 100px;
        }
        
        .navbar {
            background: linear-gradient(135deg, #2c3e50, #34495e) !important;
        }
        
        .card-dominio {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        .header-metro {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 15px 20px;
        }
        
        .row-expirar {
            transition: all 0.3s ease;
        }
        
        .row-expirar.bg-warning {
            background: #ffc107 !important;
        }
        
        .row-expirar.bg-danger {
            background: #e74c3c !important;
            color: white !important;
        }
        
        .row-expirar.bg-success {
            background: #27ae60 !important;
            color: white !important;
        }
        
        .row-expirar.bg-expired {
            background: #6c757d !important;
            color: white !important;
            text-decoration: line-through;
        }
        
        .btn-metro {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 8px 16px;
            transition: all 0.3s ease;
        }
        
        .btn-metro:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            color: white;
        }
        
        .badge-dias {
            font-size: 0.85rem;
            padding: 5px 10px;
            border-radius: 20px;
        }
        
        .table-responsive {
            border-radius: 0 0 15px 15px;
        }
    </style>
</head>
<body>

<!-- Navbar Fijo -->
<nav class="navbar navbar-expand-lg navbar-dark sticky-top">
    <div class="container">
        <a class="navbar-brand font-weight-bold" href="?">
            <i class="fas fa-globe mr-2"></i>Dominios
        </a>
        <span class="navbar-text text-white">
            <i class="fas fa-robot mr-1"></i>Modelo: MiniMax-M2.5
        </span>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="https://www.google.com" target="_blank">
                        <i class="fas fa-search mr-1"></i>Google
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?accion=listado">
                        <i class="fas fa-list mr-1"></i>Ver Todos
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?accion=agregar">
                        <i class="fas fa-plus mr-1"></i>Agregar
                    </a>
                </li>
            </ul>
        </div>
    </div>
</nav>

<!-- Contenido Principal -->
<div class="main-container">
    <div class="container">
        
        <!-- Mensajes -->
        <?php if (!empty($mensaje)): ?>
        <div class="alert alert-<?php echo $tipo_mensaje; ?> alert-dismissible fade show" role="alert">
            <i class="fas <?php echo ($tipo_mensaje === 'success') ? 'fa-check-circle' : 'fa-exclamation-circle'; ?> mr-2"></i>
            <?php echo htmlspecialchars($mensaje); ?>
            <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
        </div>
        <?php endif; ?>
        
        <!-- ============================================ -->
        <!-- LISTADO DE DOMINIOS -->
        <!-- ============================================ -->
        <?php if ($accion === 'listado'): ?>
        
        <div class="card-dominio mb-4">
            <div class="header-metro">
                <div class="d-flex justify-content-between align-items-center flex-wrap">
                    <h4 class="mb-0"><i class="fas fa-globe mr-2"></i>Control de Dominios</h4>
                    <a href="?accion=agregar" class="btn btn-sm btn-light">
                        <i class="fas fa-plus mr-1"></i>Nuevo Dominio
                    </a>
                </div>
            </div>
            
            <!-- Filtros -->
            <div class="p-3 bg-light">
                <form method="GET" class="mb-0">
                    <input type="hidden" name="accion" value="listado">
                    <div class="row">
                        <div class="col-md-2">
                            <input type="text" class="form-control" name="busqueda" placeholder="Buscar dominio..." value="<?php echo htmlspecialchars($busqueda); ?>">
                        </div>
                        <div class="col-md-2">
                            <select class="form-control" name="f_ext">
                                <option value="">Todas las ext.</option>
                                <option value="com" <?php echo ($f_ext === 'com') ? 'selected' : ''; ?>>.com</option>
                                <option value="net" <?php echo ($f_ext === 'net') ? 'selected' : ''; ?>>.net</option>
                                <option value="org" <?php echo ($f_ext === 'org') ? 'selected' : ''; ?>>.org</option>
                                <option value="info" <?php echo ($f_ext === 'info') ? 'selected' : ''; ?>>.info</option>
                                <option value="monster" <?php echo ($f_ext === 'monster') ? 'selected' : ''; ?>>.monster</option>
                                <option value="xyz" <?php echo ($f_ext === 'xyz') ? 'selected' : ''; ?>>.xyz</option>
                                <option value="vip" <?php echo ($f_ext === 'vip') ? 'selected' : ''; ?>>.vip</option>
                                <option value="mom" <?php echo ($f_ext === 'mom') ? 'selected' : ''; ?>>.mom</option>
                                <option value="mx" <?php echo ($f_ext === 'mx') ? 'selected' : ''; ?>>.mx</option>
                                <option value="com.mx" <?php echo ($f_ext === 'com.mx') ? 'selected' : ''; ?>>.com.mx</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <select class="form-control" name="f_type">
                                <option value="">Todos los tipos</option>
                                <option value="CLIENTE" <?php echo ($f_type === 'CLIENTE') ? 'selected' : ''; ?>>Cliente</option>
                                <option value="PROPIO" <?php echo ($f_type === 'PROPIO') ? 'selected' : ''; ?>>Propio</option>
                                <option value="PROYECTO" <?php echo ($f_type === 'PROYECTO') ? 'selected' : ''; ?>>Proyecto</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <select class="form-control" name="f_iscustomer">
                                <option value="">Todos</option>
                                <option value="YES" <?php echo ($f_iscustomer === 'YES') ? 'selected' : ''; ?>>Clientes</option>
                                <option value="NO" <?php echo ($f_iscustomer === 'NO') ? 'selected' : ''; ?>>No clientes</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <select class="form-control" name="f_registrar">
                                <option value="">Todos los registrars</option>
                                <?php foreach ($registrars as $reg): ?>
                                <option value="<?php echo htmlspecialchars($reg); ?>" <?php echo ($f_registrar === $reg) ? 'selected' : ''; ?>><?php echo htmlspecialchars($reg); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <button type="submit" class="btn btn-metro btn-block"><i class="fas fa-filter mr-1"></i>Filtrar</button>
                        </div>
                    </div>
                </form>
            </div>
            
            <!-- Tabla de Dominios -->
            <div class="table-responsive">
                <table class="table table-striped table-hover mb-0">
                    </table>
                <table class="table table-sm" style="width: 100%; table-layout: auto; min-width: 800px;">    
                    <thead class="table-dark">
                        <tr>
                            <th><i class="fas fa-globe mr-1"></i>Dominio</th>
                            <th><i class="fas fa-server mr-1"></i>Name Servers</th>
                            <th><i class="fas fa-calendar mr-1"></i>Registrado</th>
                            <th><i class="fas fa-calendar-times mr-1"></i>Expira</th>
                            <th><i class="fas fa-store mr-1"></i>Registrar</th>
                            <th><i class="fas fa-tag mr-1"></i>Tipo</th>
                            <th><i class="fas fa-user mr-1"></i>Cliente</th>
                            <th><i class="fas fa-cogs mr-1"></i>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($dominios as $d): ?>
                        <tr class="row-expirar <?php echo 'bg-' . $d['dias_info']['color']; ?>">
                            <td>
                                <a href="https://<?php echo htmlspecialchars($d['dominio']); ?>" target="_blank" class="<?php echo ($d['dias_info']['color'] === 'danger' || $d['dias_info']['color'] === 'expired') ? 'text-white' : 'text-dark'; ?> font-weight-bold">
                                    <?php echo htmlspecialchars($d['dominio']); ?> <i class="fas fa-external-link-alt ml-1"></i>
                                </a>
                                <?php if (!empty($d['NOTA'])): ?>
                                <br><small class="<?php echo ($d['dias_info']['color'] === 'danger' || $d['dias_info']['color'] === 'expired') ? 'text-white-50' : 'text-muted'; ?>"><?php echo htmlspecialchars($d['NOTA']); ?></small>
                                <?php endif; ?>
                            </td>
                            <td>
                                <small><?php echo htmlspecialchars($d['servidores']); ?></small>
                            </td>
                            <td><?php echo $d['registered'] ? date('d/m/Y', strtotime($d['registered'])) : '-'; ?></td>
                            <td>
                                <?php echo $d['expiration'] ? date('d/m/Y', strtotime($d['expiration'])) : '-'; ?>
                                <?php if ($d['dias_info']['dias'] !== null): ?>
                                <br>
                                <span class="badge badge-dias <?php echo ($d['dias_info']['color'] === 'danger') ? 'bg-dark' : ($d['dias_info']['color'] === 'warning' ? 'bg-warning text-dark' : ($d['dias_info']['color'] === 'success' ? 'bg-light text-dark' : '')); ?>">
                                    <?php if ($d['dias_info']['dias'] < 0): ?>
                                    <i class="fas fa-exclamation-triangle mr-1"></i>Expirado
                                    <?php else: ?>
                                    <i class="fas fa-clock mr-1"></i><?php echo $d['dias_info']['dias']; ?> días
                                    <?php endif; ?>
                                </span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo htmlspecialchars($d['registrar']); ?></td>
                            <td>
                                <span class="badge <?php echo ($d['type'] === 'CLIENTE') ? 'badge-primary' : ($d['type'] === 'PROPIO' ? 'badge-info' : 'badge-secondary'); ?>">
                                    <?php echo htmlspecialchars($d['type']); ?>
                                </span>
                            </td>
                            <td>
                                <?php if ($d['iscustomer'] === 'YES'): ?>
                                <i class="fas fa-check-circle text-success"></i>
                                <?php else: ?>
                                <i class="fas fa-times-circle text-muted"></i>
                                <?php endif; ?>
                            </td>
                            <td>
                                <a href="?accion=actualizar&dominio=<?php echo urlencode($d['dominio']); ?>" class="btn btn-sm btn-info" title="Actualizar WHOIS">
                                    <i class="fas fa-sync-alt"></i>
                                </a>
                                <a href="?accion=editar&dominio=<?php echo urlencode($d['dominio']); ?>" class="btn btn-sm btn-warning" title="Editar">
                                    <i class="fas fa-edit"></i>
                                </a>
                                <a href="?accion=eliminar&dominio=<?php echo urlencode($d['dominio']); ?>" class="btn btn-sm btn-danger" title="Eliminar" onclick="return confirm('¿Eliminar dominio <?php echo htmlspecialchars($d['dominio']); ?>?')">
                                    <i class="fas fa-trash"></i>
                                </a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <?php if (empty($dominios)): ?>
                <div class="text-center text-muted py-5">
                    <i class="fas fa-globe fa-3x mb-3"></i>
                    <p>No hay dominios registrados</p>
                    <a href="?accion=agregar" class="btn btn-metro">
                        <i class="fas fa-plus mr-2"></i>Agregar Primer Dominio
                    </a>
                </div>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
        
        <!-- ============================================ -->
        <!-- AGREGAR DOMINIO -->
        <!-- ============================================ -->
        <?php if ($accion === 'agregar'): ?>
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card-dominio">
                    <div class="header-metro">
                        <h4 class="mb-0"><i class="fas fa-plus mr-2"></i>Agregar Dominio</h4>
                    </div>
                    <div class="card-body p-4">
                        <form method="POST" action="?accion=agregar">
                            <div class="form-group">
                                <label><i class="fas fa-globe mr-2"></i>Dominio</label>
                                <input type="text" name="dominio" class="form-control" placeholder="ejemplo.com" required>
                                <small class="text-muted">Extensiones permitidas: <?php echo implode(', ', $extensiones_validas); ?></small>
                            </div>
                            
                            <div class="form-group">
                                <label><i class="fas fa-tag mr-2"></i>Tipo</label>
                                <select name="type" class="form-control">
                                    <option value="CLIENTE">Cliente</option>
                                    <option value="PROPIO">Propio</option>
                                    <option value="PROYECTO">Proyecto</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label><i class="fas fa-user mr-2"></i>¿Es cliente?</label>
                                <select name="iscustomer" class="form-control">
                                    <option value="NO">No</option>
                                    <option value="YES">Sí</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label><i class="fas fa-comment mr-2"></i>Nota</label>
                                <textarea name="NOTA" class="form-control" rows="3" placeholder="Notas sobre este dominio..."></textarea>
                            </div>
                            
                            <button type="submit" class="btn btn-metro btn-block">
                                <i class="fas fa-plus mr-2"></i>Agregar y Consultar WHOIS
                            </button>
                            <a href="?" class="btn btn-outline-secondary btn-block mt-2">Cancelar</a>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>
        
        <!-- ============================================ -->
        <!-- EDITAR DOMINIO -->
        <!-- ============================================ -->
        <?php if ($accion === 'editar' && $dominio_editar): ?>
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card-dominio">
                    <div class="header-metro">
                        <h4 class="mb-0"><i class="fas fa-edit mr-2"></i>Editar Dominio</h4>
                    </div>
                    <div class="card-body p-4">
                        <form method="POST" action="?accion=editar">
                            <input type="hidden" name="dominio_original" value="<?php echo htmlspecialchars($dominio_editar['dominio']); ?>">
                            
                            <div class="form-group">
                                <label><i class="fas fa-globe mr-2"></i>Dominio</label>
                                <input type="text" name="dominio" class="form-control" value="<?php echo htmlspecialchars($dominio_editar['dominio']); ?>" required>
                            </div>
                            
                            <div class="form-group">
                                <label><i class="fas fa-server mr-2"></i>Name Servers</label>
                                <input type="text" class="form-control" value="<?php echo htmlspecialchars($dominio_editar['servidores']); ?>" readonly>
                                <small class="text-muted">Usa el botón actualizar para modificar</small>
                            </div>
                            
                            <div class="form-group">
                                <label><i class="fas fa-tag mr-2"></i>Tipo</label>
                                <select name="type" class="form-control">
                                    <option value="CLIENTE" <?php echo ($dominio_editar['type'] === 'CLIENTE') ? 'selected' : ''; ?>>Cliente</option>
                                    <option value="PROPIO" <?php echo ($dominio_editar['type'] === 'PROPIO') ? 'selected' : ''; ?>>Propio</option>
                                    <option value="PROYECTO" <?php echo ($dominio_editar['type'] === 'PROYECTO') ? 'selected' : ''; ?>>Proyecto</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label><i class="fas fa-user mr-2"></i>¿Es cliente?</label>
                                <select name="iscustomer" class="form-control">
                                    <option value="NO" <?php echo ($dominio_editar['iscustomer'] === 'NO') ? 'selected' : ''; ?>>No</option>
                                    <option value="YES" <?php echo ($dominio_editar['iscustomer'] === 'YES') ? 'selected' : ''; ?>>Sí</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label><i class="fas fa-eye mr-2"></i>Visible</label>
                                <select name="showit" class="form-control">
                                    <option value="YES" <?php echo ($dominio_editar['showit'] === 'YES') ? 'selected' : ''; ?>>Sí</option>
                                    <option value="NO" <?php echo ($dominio_editar['showit'] === 'NO') ? 'selected' : ''; ?>>No</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label><i class="fas fa-comment mr-2"></i>Nota</label>
                                <textarea name="NOTA" class="form-control" rows="3"><?php echo htmlspecialchars($dominio_editar['NOTA']); ?></textarea>
                            </div>
                            
                            <button type="submit" class="btn btn-metro btn-block">
                                <i class="fas fa-save mr-2"></i>Guardar Cambios
                            </button>
                            <a href="?" class="btn btn-outline-secondary btn-block mt-2">Cancelar</a>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>
        
    </div>
</div>

<!-- Footer Fijo -->
<footer class="py-2" style="background: linear-gradient(135deg, #2c3e50, #34495e); color: white; position: fixed; bottom: 0; width: 100%; z-index: 1000;">
    <div class="container text-center">
        <small>
            <i class="fas fa-globe mr-1"></i>Dominios | 
            <i class="fas fa-code mr-1"></i>PHP <?php echo phpversion(); ?> | 
            <i class="fas fa-database mr-1"></i>MariaDB | 
            <i class="fas fa-robot mr-1"></i>MiniMax-M2.5
        </small>
    </div>
</footer>

<!-- Bootstrap & jQuery -->
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>