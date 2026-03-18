<?php
// ============================================
// SISTEMA DE CONTROL DE DOMINIOS
// PHP 8.x | Bootstrap 4.6.x | Font Awesome
// ============================================

require_once 'config.php';

// ============================================
// FUNCIONES WHOIS
// ============================================

/**
 * Obtiene información WHOIS para dominios internacionales
 * Soporta: .com .net .org .info .monster .xyz .vip .mom
 */
function getWhoisInternational($domain) {
    $whoisServers = [
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'org' => 'whois.pir.org',
        'info' => 'whois.afilias.net',
        'monster' => 'whois.nic.monster',
        'xyz' => 'whois.nic.xyz',
        'vip' => 'whois.nic.vip',
        'mom' => 'whois.nic.mom'
    ];
    
    $parts = explode('.', $domain);
    $tld = end($parts);
    
    if (!isset($whoisServers[$tld])) {
        return false;
    }
    
    $server = $whoisServers[$tld];
    $data = ['registered' => null, 'expiration' => null, 'registrar' => null, 'servers' => ''];
    
    $socket = fsockopen($server, 43, $errno, $errstr, 10);
    if (!$socket) return false;
    
    fwrite($socket, $domain . "\r\n");
    $response = '';
    while (!feof($socket)) {
        $response .= fgets($socket, 128);
    }
    fclose($socket);
    
    // Parsear fechas
    if (preg_match('/Creation Date:\s*(\d{4}-\d{2}-\d{2})/i', $response, $m)) {
        $data['registered'] = $m[1];
    } elseif (preg_match('/Created On:\s*(\d{4}-\d{2}-\d{2})/i', $response, $m)) {
        $data['registered'] = $m[1];
    }
    
    if (preg_match('/Registry Expiry Date:\s*(\d{4}-\d{2}-\d{2})/i', $response, $m)) {
        $data['expiration'] = $m[1];
    } elseif (preg_match('/Expiration Date:\s*(\d{4}-\d{2}-\d{2})/i', $response, $m)) {
        $data['expiration'] = $m[1];
    } elseif (preg_match('/Expires On:\s*(\d{4}-\d{2}-\d{2})/i', $response, $m)) {
        $data['expiration'] = $m[1];
    }
    
    // Parsear registrador
    if (preg_match('/Registrar:\s*(.+)/i', $response, $m)) {
        $data['registrar'] = trim($m[1]);
    } elseif (preg_match('/Sponsoring Registrar:\s*(.+)/i', $response, $m)) {
        $data['registrar'] = trim($m[1]);
    }
    
    // Parsear name servers
    if (preg_match_all('/Name Server:\s*([^\s]+)/i', $response, $m)) {
        $data['servers'] = implode(', ', array_slice(array_unique($m[1]), 0, 4));
    }
    
    return $data;
}

/**
 * Obtiene información WHOIS para dominios .mx y .com.mx
 * Usa whois.nic.mx
 */
function getWhoisMX($domain) {
    $server = 'whois.nic.mx';
    $data = ['registered' => null, 'expiration' => null, 'registrar' => null, 'servers' => ''];
    
    $socket = fsockopen($server, 43, $errno, $errstr, 10);
    if (!$socket) return false;
    
    fwrite($socket, $domain . "\r\n");
    $response = '';
    while (!feof($socket)) {
        $response .= fgets($socket, 128);
    }
    fclose($socket);
    
    // Parsear fechas formato MX
    if (preg_match('/Created:\s*(\d{4}-\d{2}-\d{2})/i', $response, $m)) {
        $data['registered'] = $m[1];
    }
    
    if (preg_match('/Expires:\s*(\d{4}-\d{2}-\d{2})/i', $response, $m)) {
        $data['expiration'] = $m[1];
    }
    
    // Parsear registrador
    if (preg_match('/Registrar:\s*(.+)/i', $response, $m)) {
        $data['registrar'] = trim($m[1]);
    }
    
    // Parsear DNS
    if (preg_match_all('/DNS:\s*([^\s]+)/i', $response, $m)) {
        $data['servers'] = implode(', ', $m[1]);
    }
    
    return $data;
}

/**
 * Determina qué función WHOIS usar según la extensión
 */
function updateDomainWhois($domain, $link) {
    $parts = explode('.', $domain);
    $tld = end($parts);
    
    // Dominios MX usan función especial
    if ($tld === 'mx' || (count($parts) >= 2 && $parts[count($parts)-2] === 'com' && $tld === 'mx')) {
        $data = getWhoisMX($domain);
    } else {
        $data = getWhoisInternational($domain);
    }
    
    if ($data && ($data['expiration'] || $data['registrar'])) {
        $stmt = mysqli_prepare($link, "UPDATE dominios2020 SET 
            registered = ?, 
            expiration = ?, 
            registrar = ?, 
            servidores = ?,
            last_updated = CURDATE()
            WHERE dominio = ?");
        
        mysqli_stmt_bind_param($stmt, 'sssss', 
            $data['registered'], 
            $data['expiration'], 
            $data['registrar'], 
            $data['servers'],
            $domain
        );
        
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
        
        return true;
    }
    
    return false;
}

// ============================================
// PROCESAMIENTO DE ACCIONES
// ============================================

$message = '';
$messageType = '';

// Actualizar WHOIS de un dominio específico
if (isset($_GET['update']) && !empty($_GET['update'])) {
    $domainToUpdate = mysqli_real_escape_string($link, $_GET['update']);
    if (updateDomainWhois($domainToUpdate, $link)) {
        $message = "Dominio $domainToUpdate actualizado correctamente";
        $messageType = "success";
    } else {
        $message = "No se pudo actualizar $domainToUpdate";
        $messageType = "danger";
    }
}

// ============================================
// FILTROS
// ============================================

$where = ["showit = 'YES'"];
$params = [];
$types = "";

$filterExtension = $_GET['extension'] ?? '';
$filterType = $_GET['type'] ?? '';
$filterCustomer = $_GET['iscustomer'] ?? '';
$filterRegistrar = $_GET['registrar'] ?? '';

if ($filterExtension) {
    $where[] = "dominio LIKE ?";
    $params[] = "%.$filterExtension";
    $types .= "s";
}
if ($filterType) {
    $where[] = "type = ?";
    $params[] = $filterType;
    $types .= "s";
}
if ($filterCustomer) {
    $where[] = "iscustomer = ?";
    $params[] = $filterCustomer;
    $types .= "s";
}
if ($filterRegistrar) {
    $where[] = "registrar LIKE ?";
    $params[] = "%$filterRegistrar%";
    $types .= "s";
}

$whereClause = implode(' AND ', $where);

// ============================================
// CONSULTA PRINCIPAL
// ============================================

$sql = "SELECT *, 
        DATEDIFF(expiration, CURDATE()) as days_left,
        CASE 
            WHEN DATEDIFF(expiration, CURDATE()) < 14 THEN 'table-danger'
            WHEN DATEDIFF(expiration, CURDATE()) < 60 THEN 'table-warning'
            WHEN DATEDIFF(expiration, CURDATE()) > 370 THEN 'table-success'
            ELSE ''
        END as row_class
        FROM dominios2020 
        WHERE $whereClause
        ORDER BY expiration ASC, dominio ASC";

$stmt = mysqli_prepare($link, $sql);
if ($types && $params) {
    mysqli_stmt_bind_param($stmt, $types, ...$params);
}
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

// Obtener valores únicos para filtros
$extensions = ['com', 'net', 'org', 'info', 'monster', 'xyz', 'vip', 'mom', 'mx', 'com.mx'];
$typesList = [];
$registrarsList = [];
$customersList = ['YES', 'NO'];

$resFilters = mysqli_query($link, "SELECT DISTINCT type FROM dominios2020 WHERE showit = 'YES' ORDER BY type");
while ($row = mysqli_fetch_assoc($resFilters)) {
    if ($row['type']) $typesList[] = $row['type'];
}

$resReg = mysqli_query($link, "SELECT DISTINCT registrar FROM dominios2020 WHERE showit = 'YES' AND registrar IS NOT NULL ORDER BY registrar");
while ($row = mysqli_fetch_assoc($resReg)) {
    if ($row['registrar']) $registrarsList[] = $row['registrar'];
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Control de Dominios</title>
    
    <!-- Bootstrap 4.6.2 CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --accent-color: #3498db;
        }
        
        body {
            padding-top: 70px;
            padding-bottom: 60px;
            background-color: #ecf0f1;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .navbar-brand {
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        
        .model-version {
            color: rgba(255,255,255,0.7);
            font-size: 0.85rem;
            border-left: 1px solid rgba(255,255,255,0.3);
            padding-left: 15px;
            margin-left: 15px;
        }
        
        .card {
            border: none;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            margin-bottom: 20px;
        }
        
        .card-header {
            background-color: #fff;
            border-bottom: 2px solid #e9ecef;
            font-weight: 600;
            color: var(--primary-color);
        }
        
        .table {
            background-color: #fff;
            font-size: 0.9rem;
        }
        
        .table th {
            border-top: none;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
            color: #6c757d;
        }
        
        .table td {
            vertical-align: middle;
        }
        
        .domain-link {
            font-weight: 600;
            color: var(--accent-color);
            text-decoration: none;
        }
        
        .domain-link:hover {
            color: #2980b9;
            text-decoration: none;
        }
        
        .badge-customer {
            background-color: #27ae60;
            color: white;
        }
        
        .badge-internal {
            background-color: #95a5a6;
            color: white;
        }
        
        .days-badge {
            font-weight: 600;
            padding: 6px 12px;
            border-radius: 20px;
        }
        
        .btn-update {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
            color: white;
        }
        
        .btn-update:hover {
            background-color: #2980b9;
            border-color: #2980b9;
        }
        
        .footer {
            position: fixed;
            bottom: 0;
            width: 100%;
            height: 50px;
            background-color: var(--primary-color);
            color: rgba(255,255,255,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.9rem;
            z-index: 1030;
        }
        
        .filter-section {
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .form-control:focus {
            border-color: var(--accent-color);
            box-shadow: 0 0 0 0.2rem rgba(52, 152, 219, 0.25);
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #6c757d;
        }
        
        .empty-state i {
            font-size: 4rem;
            margin-bottom: 20px;
            color: #bdc3c7;
        }
    </style>
</head>
<body>

    <!-- Navbar Fija -->
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="fas fa-globe-americas mr-2"></i>
                Control de Dominios
            </a>
            <div class="navbar-nav ml-auto">
                <a class="nav-link" href="https://google.com" target="_blank">
                    <i class="fab fa-google mr-1"></i> Google
                </a>
                <span class="model-version">
                    <i class="fas fa-robot mr-1"></i> Model: Kimi K2.5
                </span>
            </div>
        </div>
    </nav>

    <!-- Contenido Principal -->
    <div class="container-fluid">
        
        <?php if ($message): ?>
        <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show" role="alert">
            <i class="fas fa-<?php echo $messageType === 'success' ? 'check-circle' : 'exclamation-triangle'; ?> mr-2"></i>
            <?php echo htmlspecialchars($message); ?>
            <button type="button" class="close" data-dismiss="alert">
                <span>&times;</span>
            </button>
        </div>
        <?php endif; ?>

        <!-- Filtros -->
        <div class="filter-section">
            <h5 class="mb-3"><i class="fas fa-filter mr-2"></i>Filtros</h5>
            <form method="GET" class="row">
                <div class="col-md-3 mb-2">
                    <label class="small text-muted">Extensión</label>
                    <select name="extension" class="form-control form-control-sm">
                        <option value="">Todas</option>
                        <?php foreach ($extensions as $ext): ?>
                        <option value="<?php echo $ext; ?>" <?php echo $filterExtension === $ext ? 'selected' : ''; ?>>
                            .<?php echo $ext; ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3 mb-2">
                    <label class="small text-muted">Tipo</label>
                    <select name="type" class="form-control form-control-sm">
                        <option value="">Todos</option>
                        <?php foreach ($typesList as $type): ?>
                        <option value="<?php echo htmlspecialchars($type); ?>" <?php echo $filterType === $type ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($type); ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-2 mb-2">
                    <label class="small text-muted">Cliente</label>
                    <select name="iscustomer" class="form-control form-control-sm">
                        <option value="">Todos</option>
                        <option value="YES" <?php echo $filterCustomer === 'YES' ? 'selected' : ''; ?>>Sí</option>
                        <option value="NO" <?php echo $filterCustomer === 'NO' ? 'selected' : ''; ?>>No</option>
                    </select>
                </div>
                <div class="col-md-3 mb-2">
                    <label class="small text-muted">Registrador</label>
                    <select name="registrar" class="form-control form-control-sm">
                        <option value="">Todos</option>
                        <?php foreach ($registrarsList as $reg): ?>
                        <option value="<?php echo htmlspecialchars($reg); ?>" <?php echo $filterRegistrar === $reg ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($reg); ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-1 mb-2 d-flex align-items-end">
                    <button type="submit" class="btn btn-primary btn-sm btn-block">
                        <i class="fas fa-search"></i>
                    </button>
                </div>
            </form>
        </div>

        <!-- Tabla de Dominios -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span><i class="fas fa-list mr-2"></i>Listado de Dominios</span>
                <span class="badge badge-secondary"><?php echo mysqli_num_rows($result); ?> dominios</span>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
                        <thead class="thead-light">
                            <tr>
                                <th>Dominio</th>
                                <th>Registrador</th>
                                <th>Tipo</th>
                                <th>Cliente</th>
                                <th>Registro</th>
                                <th>Expiración</th>
                                <th>Días Rest.</th>
                                <th>DNS</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (mysqli_num_rows($result) > 0): ?>
                                <?php while ($row = mysqli_fetch_assoc($result)): 
                                    $daysLeft = $row['days_left'] ?? null;
                                    $rowClass = $row['row_class'] ?? '';
                                    
                                    // Determinar color del badge de días
                                    $badgeClass = 'badge-secondary';
                                    if ($daysLeft !== null) {
                                        if ($daysLeft < 14) $badgeClass = 'badge-danger';
                                        elseif ($daysLeft < 60) $badgeClass = 'badge-warning text-dark';
                                        elseif ($daysLeft > 370) $badgeClass = 'badge-success';
                                    }
                                ?>
                                <tr class="<?php echo $rowClass; ?>">
                                    <td>
                                        <a href="https://<?php echo htmlspecialchars($row['dominio']); ?>" 
                                           target="_blank" 
                                           class="domain-link">
                                            <i class="fas fa-external-link-alt mr-1 small"></i>
                                            <?php echo htmlspecialchars($row['dominio']); ?>
                                        </a>
                                    </td>
                                    <td><?php echo htmlspecialchars($row['registrar'] ?? 'N/A'); ?></td>
                                    <td>
                                        <span class="badge badge-info">
                                            <?php echo htmlspecialchars($row['type']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($row['iscustomer'] === 'YES'): ?>
                                            <span class="badge badge-customer">Sí</span>
                                        <?php else: ?>
                                            <span class="badge badge-internal">No</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php echo $row['registered'] ? date('d/m/Y', strtotime($row['registered'])) : '-'; ?></td>
                                    <td><?php echo $row['expiration'] ? date('d/m/Y', strtotime($row['expiration'])) : '-'; ?></td>
                                    <td>
                                        <?php if ($daysLeft !== null): ?>
                                            <span class="badge <?php echo $badgeClass; ?> days-badge">
                                                <?php echo $daysLeft; ?> días
                                            </span>
                                        <?php else: ?>
                                            <span class="badge badge-secondary">N/A</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="small text-muted" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                                        <?php echo htmlspecialchars($row['servidores'] ?? 'N/A'); ?>
                                    </td>
                                    <td>
                                        <a href="?update=<?php echo urlencode($row['dominio']); ?>&<?php echo http_build_query($_GET); ?>" 
                                           class="btn btn-update btn-sm"
                                           title="Actualizar WHOIS">
                                            <i class="fas fa-sync-alt"></i>
                                        </a>
                                    </td>
                                </tr>
                                <?php endwhile; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="9">
                                        <div class="empty-state">
                                            <i class="fas fa-inbox"></i>
                                            <h5>No se encontraron dominios</h5>
                                            <p>Intenta ajustar los filtros o agrega nuevos dominios a la base de datos.</p>
                                        </div>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Leyenda de colores -->
        <div class="card mt-3">
            <div class="card-body py-2">
                <small class="text-muted">
                    <strong><i class="fas fa-info-circle mr-1"></i>Leyenda:</strong>
                    <span class="badge badge-danger ml-2">Rojo</span> Expira en < 14 días
                    <span class="badge badge-warning text-dark ml-2">Amarillo</span> Expira en < 60 días  
                    <span class="badge badge-success ml-2">Verde</span> Expira en > 370 días
                    <span class="badge badge-light border ml-2">Blanco</span> Normal (60-370 días)
                </small>
            </div>
        </div>
        
    </div>

    <!-- Footer Fijo -->
    <footer class="footer">
        <div class="container text-center">
            <i class="fas fa-code mr-1"></i> Sistema de Control de Dominios &copy; <?php echo date('Y'); ?> 
            | Desarrollado con <i class="fas fa-heart text-danger mx-1"></i> usando PHP 8 & Bootstrap 4.6
        </div>
    </footer>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
    
</body>
</html>