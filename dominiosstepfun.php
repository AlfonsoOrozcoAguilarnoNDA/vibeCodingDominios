<?php
// Sistema de Control de Dominios - Step 3.5 Flash
// Requiere: config.php con conexión $link a MySQL

// Incluir configuración de base de datos
require_once 'config.php';

// Procesar actualización de dominio (WHOIS)
if (isset($_POST['actualizar_dominio']) && !empty($_POST['dominio'])) {
    $dominio = mysqli_real_escape_string($link, $_POST['dominio']);
    
    // Función para actualizar datos vía WHOIS (simulada - implementar según tu API/WHOIS real)
    function actualizarDominioWhois($dominio, $link) {
        // Aquí deberías implementar la lógica real de consulta WHOIS
        // Ejemplo usando whois CLI o API externa
        $whois_data = [
            'registered' => date('Y-m-d', strtotime('-1 year')),
            'expiration' => date('Y-m-d', strtotime('+1 year')),
            'registrar' => 'Registrador Ejemplo',
            'servidores' => 'ns3.ejemplo.com, ns4.ejemplo.com'
        ];
        
        $query = "UPDATE dominios2020 SET 
            registered = '{$whois_data['registered']}',
            expiration = '{$whois_data['expiration']}',
            registrar = '{$whois_data['registrar']}',
            servidores = '{$whois_data['servidores']}',
            last_updated = CURDATE()
            WHERE dominio = '$dominio'";
        
        return mysqli_query($link, $query);
    }
    
    if (actualizarDominioWhois($dominio, $link)) {
        $_SESSION['mensaje'] = "Dominio actualizado correctamente";
    } else {
        $_SESSION['error'] = "Error actualizando dominio";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Obtener valores únicos para filtros
$tipos = [];
$iscustomer = [];
$registradores = [];

$res = mysqli_query($link, "SELECT DISTINCT type FROM dominios2020 ORDER BY type");
while ($row = mysqli_fetch_assoc($res)) $tipos[] = $row['type'];

$res = mysqli_query($link, "SELECT DISTINCT iscustomer FROM dominios2020 ORDER BY iscustomer");
while ($row = mysqli_fetch_assoc($res)) $iscustomer[] = $row['iscustomer'];

$res = mysqli_query($link, "SELECT DISTINCT registrar FROM dominios2020 WHERE registrar IS NOT NULL ORDER BY registrar");
while ($row = mysqli_fetch_assoc($res)) $registradores[] = $row['registrar'];

// Extensiones disponibles
$extensiones = ['.com', '.net', '.org', '.info', '.monster', '.xyz', '.vip', '.mom', '.mx', '.com.mx'];

// Construir consulta con filtros
$where = [];
$params = [];

if (!empty($_GET['extension']) && in_array($_GET['extension'], $extensiones)) {
    $ext = $_GET['extension'];
    if ($ext == '.mx') {
        $where[] = "dominio LIKE '%.mx' AND dominio NOT LIKE '%.com.mx'";
    } elseif ($ext == '.com.mx') {
        $where[] = "dominio LIKE '%.com.mx'";
    } else {
        $where[] = "dominio LIKE '%" . mysqli_real_escape_string($link, $ext) . "'";
    }
}

if (!empty($_GET['type']) && in_array($_GET['type'], $tipos)) {
    $where[] = "type = '" . mysqli_real_escape_string($link, $_GET['type']) . "'";
}

if (!empty($_GET['iscustomer']) && in_array($_GET['iscustomer'], $iscustomer)) {
    $where[] = "iscustomer = '" . mysqli_real_escape_string($link, $_GET['iscustomer']) . "'";
}

if (!empty($_GET['registrar'])) {
    $where[] = "registrar LIKE '%" . mysqli_real_escape_string($link, $_GET['registrar']) . "%'";
}

$sql = "SELECT * FROM dominios2020";
if (count($where) > 0) {
    $sql .= " WHERE " . implode(" AND ", $where);
}
$sql .= " ORDER BY expiration ASC";

$result = mysqli_query($link, $sql);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Control de Dominios - Step 3.5 Flash</title>
    <!-- Bootstrap 4.6 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --accent-color: #3498db;
        }
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .navbar {
            background-color: var(--primary-color) !important;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .footer {
            background-color: var(--primary-color);
            color: white;
            padding: 15px 0;
            position: fixed;
            bottom: 0;
            width: 100%;
            z-index: 1000;
        }
        .card {
            border: none;
            box-shadow: 0 0.125rem 0.25rem rgba(0,0,0,0.075);
            border-radius: 0.5rem;
        }
        .table-hover tbody tr:hover {
            background-color: rgba(52, 152, 219, 0.05);
        }
        .expiring-soon { background-color: #fff3cd !important; } /* Amarillo */
        .expiring-critical { background-color: #f8d7da !important; } /* Rojo */
        .expiring-safe { background-color: #d4edda !important; } /* Verde */
        .badge-type {
            font-size: 0.85em;
            padding: 0.35em 0.65em;
        }
        .btn-action {
            padding: 0.25rem 0.5rem;
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <!-- Navbar fija -->
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-globe-americas mr-2"></i>Control de Dominios
            </a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="https://google.com" target="_blank">
                            <i class="fab fa-google mr-1"></i>Google
                        </a>
                    </li>
                    <li class="nav-item">
                        <span class="nav-link text-light">
                            <i class="fas fa-robot mr-1"></i>Step 3.5 Flash
                        </span>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container" style="margin-top: 80px; margin-bottom: 80px;">
        <!-- Mensajes -->
        <?php if (isset($_SESSION['mensaje'])): ?>
            <div class="alert alert-success alert-dismissible fade show">
                <?= $_SESSION['mensaje'] ?>
                <button type="button" class="close" data-dismiss="alert">&times;</button>
            </div>
            <?php unset($_SESSION['mensaje']); ?>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['error'])): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <?= $_SESSION['error'] ?>
                <button type="button" class="close" data-dismiss="alert">&times;</button>
            </div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>

        <!-- Filtros -->
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0"><i class="fas fa-filter mr-2"></i>Filtros de Búsqueda</h5>
            </div>
            <div class="card-body">
                <form method="GET" class="row">
                    <div class="col-md-3">
                        <label>Extensión</label>
                        <select name="extension" class="form-control">
                            <option value="">-- Todas --</option>
                            <?php foreach ($extensiones as $ext): ?>
                                <option value="<?= $ext ?>" <?= (isset($_GET['extension']) && $_GET['extension'] == $ext) ? 'selected' : '' ?>>
                                    <?= $ext ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label>Tipo</label>
                        <select name="type" class="form-control">
                            <option value="">-- Todos --</option>
                            <?php foreach ($tipos as $tipo): ?>
                                <option value="<?= $tipo ?>" <?= (isset($_GET['type']) && $_GET['type'] == $tipo) ? 'selected' : '' ?>>
                                    <?= $tipo ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label>Cliente</label>
                        <select name="iscustomer" class="form-control">
                            <option value="">-- Todos --</option>
                            <?php foreach ($iscustomer as $cust): ?>
                                <option value="<?= $cust ?>" <?= (isset($_GET['iscustomer']) && $_GET['iscustomer'] == $cust) ? 'selected' : '' ?>>
                                    <?= $cust ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label>Registrador</label>
                        <input type="text" name="registrar" class="form-control" 
                               placeholder="Buscar..." value="<?= isset($_GET['registrar']) ? htmlspecialchars($_GET['registrar']) : '' ?>">
                    </div>
                    <div class="col-12 mt-3">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-search mr-1"></i> Filtrar
                        </button>
                        <a href="<?= $_SERVER['PHP_SELF'] ?>" class="btn btn-secondary ml-2">
                            <i class="fas fa-times mr-1"></i> Limpiar
                        </a>
                    </div>
                </form>
            </div>
        </div>

        <!-- Tabla de dominios -->
        <div class="card">
            <div class="card-header bg-secondary text-white d-flex justify-content-between align-items-center">
                <h5 class="mb-0"><i class="fas fa-list mr-2"></i>Listado de Dominios</h5>
                <span class="badge badge-light">
                    Total: <?= mysqli_num_rows($result) ?> dominios
                </span>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
                        <thead class="thead-light">
                            <tr>
                                <th>Dominio</th>
                                <th>Extensión</th>
                                <th>Registrado</th>
                                <th>Expira</th>
                                <th>Días</th>
                                <th>Servidores</th>
                                <th>Registrador</th>
                                <th>Tipo</th>
                                <th>Cliente</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (mysqli_num_rows($result) > 0): ?>
                                <?php while ($row = mysqli_fetch_assoc($result)): 
                                    $hoy = new DateTime();
                                    $expira = new DateTime($row['expiration']);
                                    $dias = $hoy->diff($expira)->days;
                                    if ($expira < $hoy) $dias = -$dias;
                                    
                                    // Determinar clase de color
                                    $rowClass = '';
                                    if ($dias < 14) {
                                        $rowClass = 'expiring-critical';
                                    } elseif ($dias < 60) {
                                        $rowClass = 'expiring-soon';
                                    } elseif ($dias > 370) {
                                        $rowClass = 'expiring-safe';
                                    }
                                    
                                    // Extraer extensión
                                    $partes = explode('.', $row['dominio']);
                                    $extension = '.' . end($partes);
                                ?>
                                <tr class="<?= $rowClass ?>">
                                    <td>
                                        <a href="http://<?= htmlspecialchars($row['dominio']) ?>" 
                                           target="_blank" 
                                           class="font-weight-bold text-primary">
                                            <i class="fas fa-external-link-alt mr-1"></i>
                                            <?= htmlspecialchars($row['dominio']) ?>
                                        </a>
                                    </td>
                                    <td><span class="badge badge-info"><?= $extension ?></span></td>
                                    <td><?= $row['registered'] ? date('d/m/Y', strtotime($row['registered'])) : 'N/A' ?></td>
                                    <td><strong><?= $row['expiration'] ? date('d/m/Y', strtotime($row['expiration'])) : 'N/A' ?></strong></td>
                                    <td>
                                        <?php if ($dias >= 0): ?>
                                            <span class="badge <?= $dias < 14 ? 'badge-danger' : ($dias < 60 ? 'badge-warning' : 'badge-success') ?>">
                                                <?= $dias ?> días
                                            </span>
                                        <?php else: ?>
                                            <span class="badge badge-danger">¡Vencido!</span>
                                        <?php endif; ?>
                                    </td>
                                    <td><small><?= htmlspecialchars($row['servidores']) ?></small></td>
                                    <td><?= htmlspecialchars($row['registrar']) ?></td>
                                    <td><span class="badge badge-type badge-secondary"><?= htmlspecialchars($row['type']) ?></span></td>
                                    <td>
                                        <span class="badge <?= $row['iscustomer'] == 'YES' ? 'badge-success' : 'badge-light' ?>">
                                            <?= $row['iscustomer'] ?>
                                        </span>
                                    </td>
                                    <td>
                                        <form method="POST" style="display:inline;">
                                            <input type="hidden" name="dominio" value="<?= htmlspecialchars($row['dominio']) ?>">
                                            <button type="submit" name="actualizar_dominio" 
                                                    class="btn btn-sm btn-outline-primary btn-action"
                                                    onclick="return confirm('¿Actualizar datos WHOIS para <?= htmlspecialchars($row['dominio']) ?>?')">
                                                <i class="fas fa-sync-alt mr-1"></i>Actualizar
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                                <?php endwhile; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="10" class="text-center py-4">
                                        <div class="alert alert-info mb-0">
                                            <i class="fas fa-info-circle mr-2"></i>No se encontraron dominios con los filtros aplicados
                                        </div>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer fijo -->
    <footer class="footer text-center">
        <div class="container">
            <p class="mb-0">
                <i class="fas fa-code mr-2"></i>Desarrollado por Step 3.5 Flash | 
                <i class="far fa-calendar-alt mr-2 ml-3"></i><?= date('d/m/Y') ?> | 
                <i class="fas fa-server mr-2 ml-3"></i>MySQL Procedural
            </p>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>