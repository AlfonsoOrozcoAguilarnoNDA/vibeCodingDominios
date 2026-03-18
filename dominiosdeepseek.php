<?php
// control_dominios.php
session_start();
require_once 'config.php';

// Procesar actualización WHOIS
if (isset($_GET['update'])) {
    $dominio = $_GET['update'];
    $whois_data = obtenerWhois($dominio);
    if ($whois_data) {
        $sql = "UPDATE dominios2020 SET 
                servidores = ?,
                registered = ?,
                expiration = ?,
                registrar = ?,
                last_updated = NOW()
                WHERE dominio = ?";
        $stmt = mysqli_prepare($link, $sql);
        mysqli_stmt_bind_param($stmt, 'sssss', 
            $whois_data['servidores'],
            $whois_data['registered'],
            $whois_data['expiration'],
            $whois_data['registrar'],
            $dominio
        );
        mysqli_stmt_execute($stmt);
    }
    header("Location: " . strtok($_SERVER["REQUEST_URI"], '?'));
    exit;
}

// Función para obtener datos WHOIS
function obtenerWhois($dominio) {
    $partes = explode('.', $dominio);
    $extension = end($partes);
    
    // Simulación de WHOIS - En producción conectar con API real
    $data = [
        'servidores' => 'ns1.ejemplo.com, ns2.ejemplo.com',
        'registered' => date('Y-m-d', strtotime('-2 years')),
        'expiration' => date('Y-m-d', strtotime('+1 year')),
        'registrar' => 'GoDaddy'
    ];
    
    // Para dominios MX y COM.MX (reglas especiales)
    if ($extension == 'mx' || strpos($dominio, '.com.mx') !== false) {
        $data['registrar'] = 'NIC Mexico';
    }
    
    return $data;
}

// Construir consulta con filtros
$where = [];
$params = [];
$types = "";

if (!empty($_GET['extension'])) {
    $extension = mysqli_real_escape_string($link, $_GET['extension']);
    if ($extension == 'mx' || $extension == 'com.mx') {
        $where[] = "dominio LIKE '%." . $extension . "'";
    } else {
        $where[] = "dominio LIKE '%." . $extension . "'";
    }
}

if (!empty($_GET['type'])) {
    $where[] = "type = ?";
    $params[] = $_GET['type'];
    $types .= "s";
}

if (!empty($_GET['registrar'])) {
    $where[] = "registrar LIKE ?";
    $params[] = "%" . $_GET['registrar'] . "%";
    $types .= "s";
}

if (isset($_GET['iscustomer']) && $_GET['iscustomer'] != '') {
    $where[] = "iscustomer = ?";
    $params[] = $_GET['iscustomer'];
    $types .= "s";
}

$sql = "SELECT * FROM dominios2020";
if (!empty($where)) {
    $sql .= " WHERE " . implode(" AND ", $where);
}
$sql .= " ORDER BY expiration ASC";

$stmt = mysqli_prepare($link, $sql);
if (!empty($params)) {
    mysqli_stmt_bind_param($stmt, $types, ...$params);
}
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

// Obtener opciones para filtros
$types_result = mysqli_query($link, "SELECT DISTINCT type FROM dominios2020 ORDER BY type");
$registrars_result = mysqli_query($link, "SELECT DISTINCT registrar FROM dominios2020 WHERE registrar != '' ORDER BY registrar");
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Control de Dominios</title>
    
    <!-- Bootstrap 4.6 CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <!-- Font Awesome 5 -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --accent-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --light-bg: #ecf0f1;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            padding-top: 70px;
            padding-bottom: 60px;
        }
        
        /* Navbar fija */
        .navbar-fixed {
            position: fixed;
            top: 0;
            width: 100%;
            z-index: 1000;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .navbar-brand {
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        
        .navbar-brand i {
            color: var(--accent-color);
            margin-right: 8px;
        }
        
        .user-badge {
            background-color: rgba(255,255,255,0.2);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9rem;
        }
        
        /* Footer fijo */
        .footer-fixed {
            position: fixed;
            bottom: 0;
            width: 100%;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 10px 0;
            font-size: 0.9rem;
            z-index: 1000;
        }
        
        /* Filtros */
        .filters-card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
            margin-bottom: 25px;
            border: none;
        }
        
        .filters-card .card-header {
            background-color: var(--light-bg);
            border-bottom: 2px solid var(--accent-color);
            font-weight: 600;
            border-radius: 10px 10px 0 0 !important;
        }
        
        /* Tabla */
        .table-container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.08);
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .table {
            margin-bottom: 0;
        }
        
        .table thead th {
            border-top: none;
            border-bottom: 2px solid var(--accent-color);
            color: var(--primary-color);
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .table tbody tr {
            transition: all 0.3s ease;
        }
        
        .table tbody tr:hover {
            background-color: var(--light-bg) !important;
        }
        
        /* Colores de expiración */
        .expiring-soon {
            background-color: #fff3cd !important;
        }
        
        .expiring-critical {
            background-color: #f8d7da !important;
        }
        
        .expiring-far {
            background-color: #d4edda !important;
        }
        
        /* Botones de acción */
        .btn-action {
            padding: 4px 8px;
            margin: 0 2px;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        
        .btn-action:hover {
            transform: translateY(-2px);
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }
        
        /* Badges */
        .badge-customer {
            background-color: var(--success-color);
            color: white;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
        }
        
        .badge-internal {
            background-color: var(--secondary-color);
            color: white;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
        }
        
        /* Extension badges */
        .ext-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            background-color: var(--accent-color);
            color: white;
        }
    </style>
</head>
<body>

<!-- Navbar fija -->
<nav class="navbar navbar-expand-lg navbar-dark navbar-fixed">
    <div class="container">
        <a class="navbar-brand" href="#">
            <i class="fas fa-globe"></i>
            DomControl Pro <span style="font-size: 0.8rem; opacity: 0.7;">v2.0</span>
        </a>
        
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item">
                    <a class="nav-link" href="https://www.google.com" target="_blank">
                        <i class="fas fa-search"></i> Google
                    </a>
                </li>
            </ul>
            
            <div class="navbar-text user-badge">
                <i class="fas fa-user-circle"></i> Modelo 2024 | Admin
            </div>
        </div>
    </div>
</nav>

<!-- Contenido principal -->
<div class="container">
    <!-- Filtros -->
    <div class="card filters-card">
        <div class="card-header">
            <i class="fas fa-filter"></i> Filtros de búsqueda
        </div>
        <div class="card-body">
            <form method="GET" class="form-row align-items-end">
                <div class="form-group col-md-3">
                    <label><i class="fas fa-puzzle-piece"></i> Extensión</label>
                    <select name="extension" class="form-control">
                        <option value="">Todas las extensiones</option>
                        <option value="com" <?= ($_GET['extension'] ?? '') == 'com' ? 'selected' : '' ?>>.com</option>
                        <option value="net" <?= ($_GET['extension'] ?? '') == 'net' ? 'selected' : '' ?>>.net</option>
                        <option value="org" <?= ($_GET['extension'] ?? '') == 'org' ? 'selected' : '' ?>>.org</option>
                        <option value="info" <?= ($_GET['extension'] ?? '') == 'info' ? 'selected' : '' ?>>.info</option>
                        <option value="monster" <?= ($_GET['extension'] ?? '') == 'monster' ? 'selected' : '' ?>>.monster</option>
                        <option value="xyz" <?= ($_GET['extension'] ?? '') == 'xyz' ? 'selected' : '' ?>>.xyz</option>
                        <option value="vip" <?= ($_GET['extension'] ?? '') == 'vip' ? 'selected' : '' ?>>.vip</option>
                        <option value="mom" <?= ($_GET['extension'] ?? '') == 'mom' ? 'selected' : '' ?>>.mom</option>
                        <option value="mx" <?= ($_GET['extension'] ?? '') == 'mx' ? 'selected' : '' ?>>.mx</option>
                        <option value="com.mx" <?= ($_GET['extension'] ?? '') == 'com.mx' ? 'selected' : '' ?>>.com.mx</option>
                    </select>
                </div>
                
                <div class="form-group col-md-2">
                    <label><i class="fas fa-tag"></i> Type</label>
                    <select name="type" class="form-control">
                        <option value="">Todos</option>
                        <?php while($row = mysqli_fetch_assoc($types_result)): ?>
                            <option value="<?= htmlspecialchars($row['type']) ?>" <?= ($_GET['type'] ?? '') == $row['type'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($row['type']) ?>
                            </option>
                        <?php endwhile; ?>
                    </select>
                </div>
                
                <div class="form-group col-md-3">
                    <label><i class="fas fa-building"></i> Registrar</label>
                    <select name="registrar" class="form-control">
                        <option value="">Todos</option>
                        <?php while($row = mysqli_fetch_assoc($registrars_result)): ?>
                            <option value="<?= htmlspecialchars($row['registrar']) ?>" <?= ($_GET['registrar'] ?? '') == $row['registrar'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($row['registrar']) ?>
                            </option>
                        <?php endwhile; ?>
                    </select>
                </div>
                
                <div class="form-group col-md-2">
                    <label><i class="fas fa-user"></i> Tipo</label>
                    <select name="iscustomer" class="form-control">
                        <option value="">Todos</option>
                        <option value="YES" <?= ($_GET['iscustomer'] ?? '') == 'YES' ? 'selected' : '' ?>>Cliente</option>
                        <option value="NO" <?= ($_GET['iscustomer'] ?? '') == 'NO' ? 'selected' : '' ?>>Interno</option>
                    </select>
                </div>
                
                <div class="form-group col-md-2">
                    <button type="submit" class="btn btn-primary btn-block">
                        <i class="fas fa-search"></i> Filtrar
                    </button>
                    <a href="?" class="btn btn-secondary btn-block mt-1">
                        <i class="fas fa-undo"></i> Limpiar
                    </a>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Tabla de dominios -->
    <div class="table-container">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="mb-0"><i class="fas fa-list"></i> Listado de Dominios</h5>
            <span class="badge badge-primary">Total: <?= mysqli_num_rows($result) ?></span>
        </div>
        
        <div class="table">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>Dominio</th>
                        <th>Nameservers</th>
                        <th>Registro</th>
                        <th>Expiración</th>
                        <th>Días</th>
                        <th>Registrar</th>
                        <th>Tipo</th>
                        <th>Cliente</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (mysqli_num_rows($result) > 0): ?>
                        <?php while($row = mysqli_fetch_assoc($result)): 
                            $dias_restantes = '';
                            $row_class = '';
                            
                            if ($row['expiration']) {
                                $hoy = new DateTime();
                                $expiracion = new DateTime($row['expiration']);
                                $diferencia = $hoy->diff($expiracion);
                                $dias_restantes = $diferencia->days * ($diferencia->invert ? -1 : 1);
                                
                                if ($dias_restantes < 14 && $dias_restantes >= 0) {
                                    $row_class = 'expiring-critical';
                                } elseif ($dias_restantes < 60 && $dias_restantes >= 0) {
                                    $row_class = 'expiring-soon';
                                } elseif ($dias_restantes > 370) {
                                    $row_class = 'expiring-far';
                                }
                            }
                            
                            $extension = substr($row['dominio'], strrpos($row['dominio'], '.') + 1);
                        ?>
                            <tr class="<?= $row_class ?>">
                                <td>
                                    <strong><?= htmlspecialchars($row['dominio']) ?></strong>
                                    <br>
                                    <span class="ext-badge">.<?= $extension ?></span>
                                </td>
                                <td><small><?= htmlspecialchars(substr($row['servidores'], 0, 30)) ?><?= strlen($row['servidores']) > 30 ? '...' : '' ?></small></td>
                                <td><?= $row['registered'] ? date('d/m/Y', strtotime($row['registered'])) : '-' ?></td>
                                <td><strong><?= $row['expiration'] ? date('d/m/Y', strtotime($row['expiration'])) : '-' ?></strong></td>
                                <td>
                                    <?php if ($dias_restantes !== ''): ?>
                                        <span class="badge badge-<?= $dias_restantes < 0 ? 'secondary' : ($dias_restantes < 14 ? 'danger' : ($dias_restantes < 60 ? 'warning' : 'success')) ?>">
                                            <?= $dias_restantes < 0 ? 'Expirado' : $dias_restantes . ' días' ?>
                                        </span>
                                    <?php else: ?>
                                        -
                                    <?php endif; ?>
                                </td>
                                <td><?= htmlspecialchars($row['registrar'] ?? '-') ?></td>
                                <td><?= htmlspecialchars($row['type'] ?? '-') ?></td>
                                <td>
                                    <?php if ($row['iscustomer'] == 'YES'): ?>
                                        <span class="badge-customer"><i class="fas fa-check-circle"></i> Cliente</span>
                                    <?php else: ?>
                                        <span class="badge-internal"><i class="fas fa-building"></i> Interno</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <a href="http://<?= htmlspecialchars($row['dominio']) ?>" target="_blank" class="btn btn-sm btn-info btn-action" title="Visitar sitio">
                                        <i class="fas fa-external-link-alt"></i>
                                    </a>
                                    <a href="?update=<?= urlencode($row['dominio']) ?>" class="btn btn-sm btn-success btn-action" title="Actualizar WHOIS" onclick="return confirm('¿Actualizar datos WHOIS?')">
                                        <i class="fas fa-sync-alt"></i>
                                    </a>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="9" class="text-center py-4">
                                <i class="fas fa-database fa-2x mb-3 d-block text-muted"></i>
                                No se encontraron dominios
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Footer fijo -->
<footer class="footer-fixed">
    <div class="container text-center">
        <div class="row">
            <div class="col-md-4">
                <i class="fas fa-copyright"></i> 2024 DomControl Pro
            </div>
            <div class="col-md-4">
                <i class="fas fa-code"></i> Modelo v2.0.1
            </div>
            <div class="col-md-4">
                <i class="fas fa-shield-alt"></i> Sistema de Control de Dominios
            </div>
        </div>
    </div>
</footer>

<!-- Scripts necesarios -->
<script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>

<script>
$(document).ready(function() {
    // Tooltips
    $('[title]').tooltip();
    
    // Auto-cerrar alertas
    setTimeout(function() {
        $('.alert').fadeOut('slow');
    }, 5000);
});
</script>

</body>
</html>
<?php 
// Cerrar conexión
mysqli_close($link);
?>