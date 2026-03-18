
<?php
// config.php (asumido existente)
// Asumimos que $link es la conexión a MySQLi procedural ya establecida
require_once 'config.php';

// Función para obtener datos WHOIS (simplificada para .com, .net, .org, etc.)
function obtenerWhois($dominio) {
    $extensiones_comunes = ['.com', '.net', '.org', '.info', '.xyz', '.vip', '.monster', '.mom'];
    $es_global = false;
    foreach ($extensiones_comunes as $ext) {
        if (substr($dominio, -strlen($ext)) === $ext) {
            $es_global = true;
            break;
        }
    }

    if ($es_global) {
        return obtenerWhoisGlobal($dominio);
    } else {
        return obtenerWhoisMX($dominio);
    }
}

function obtenerWhoisGlobal($dominio) {
    $whois_server = "whois.internic.net";
    $output = "";
    if ($conn = fsockopen($whois_server, 43)) {
        fputs($conn, "$dominio\r\n");
        while (!feof($conn)) {
            $output .= fgets($conn, 128);
        }
        fclose($conn);
    }

    $registered = null;
    $expiration = null;
    $registrar = 'Unknown';
    $nameservers = [];

    $lines = explode("\n", $output);
    foreach ($lines as $line) {
        $line = trim($line);
        if (preg_match('/Creation Date|Registered on|Created on|Created:/i', $line)) {
            $parts = preg_split('/\s+/', $line, 2);
            $date_str = trim(str_replace(['Creation Date:', 'Registered on:', 'Created on:', 'Created:'], '', $line));
            if (preg_match('/\d{4}-\d{2}-\d{2}/', $date_str, $m)) {
                $registered = $m[0];
            } elseif (preg_match('/\d{2}-\w{3}-\d{4}/', $date_str, $m)) {
                $registered = date('Y-m-d', strtotime($m[0]));
            }
        } elseif (preg_match('/Expiration Date|Expires on|Expires:/i', $line)) {
            $date_str = trim(str_replace(['Expiration Date:', 'Expires on:', 'Expires:'], '', $line));
            if (preg_match('/\d{4}-\d{2}-\d{2}/', $date_str, $m)) {
                $expiration = $m[0];
            } elseif (preg_match('/\d{2}-\w{3}-\d{4}/', $date_str, $m)) {
                $expiration = date('Y-m-d', strtotime($m[0]));
            }
        } elseif (preg_match('/Registrar:/i', $line)) {
            $registrar = trim(str_replace('Registrar:', '', $line));
        } elseif (preg_match('/Name Server:/i', $line)) {
            $ns = trim(str_replace('Name Server:', '', $line));
            if (!empty($ns)) $nameservers[] = $ns;
        }
    }

    return [
        'registered' => $registered,
        'expiration' => $expiration,
        'registrar' => $registrar,
        'nameservers' => implode(', ', array_slice($nameservers, 0, 4)),
        'last_updated' => date('Y-m-d')
    ];
}

function obtenerWhoisMX($dominio) {
    // NIC México no permite WHOIS directo fácil, esto es un stub
    // En producción, usar API oficial o servicio pagado
    return [
        'registered' => null,
        'expiration' => null,
        'registrar' => 'NIC Mexico (API requerida)',
        'nameservers' => 'Consulta manual requerida',
        'last_updated' => date('Y-m-d')
    ];
}

// Actualizar dominio vía WHOIS
if (isset($_GET['update']) && !empty($_GET['update'])) {
    $dominio = mysqli_real_escape_string($link, $_GET['update']);
    $data = obtenerWhois($dominio);

    $registered = $data['registered'] ? "'" . mysqli_real_escape_string($link, $data['registered']) . "'" : 'NULL';
    $expiration = $data['expiration'] ? "'" . mysqli_real_escape_string($link, $data['expiration']) . "'" : 'NULL';
    $registrar = "'" . mysqli_real_escape_string($link, $data['registrar']) . "'";
    $nameservers = "'" . mysqli_real_escape_string($link, $data['nameservers']) . "'";
    $last_updated = "'" . mysqli_real_escape_string($link, $data['last_updated']) . "'";

    $sql_update = "UPDATE dominios2020 SET 
        registered = $registered,
        expiration = $expiration,
        registrar = $registrar,
        servidores = $nameservers,
        last_updated = $last_updated
        WHERE dominio = '$dominio'";

    mysqli_query($link, $sql_update);
}

// Filtros
$extension_filter = isset($_GET['ext']) ? $_GET['ext'] : '';
$customer_filter = isset($_GET['customer']) ? $_GET['customer'] : '';
$type_filter = isset($_GET['type']) ? $_GET['type'] : '';
$registrar_filter = isset($_GET['registrar']) ? $_GET['registrar'] : '';

$where = [];
$params = [];

if (!empty($extension_filter)) {
    $where[] = "dominio LIKE '%" . mysqli_real_escape_string($link, $extension_filter) . "'";
}
if (!empty($customer_filter)) {
    $where[] = "iscustomer = '" . mysqli_real_escape_string($link, $customer_filter) . "'";
}
if (!empty($type_filter)) {
    $where[] = "type = '" . mysqli_real_escape_string($link, $type_filter) . "'";
}
if (!empty($registrar_filter)) {
    $where[] = "registrar LIKE '%" . mysqli_real_escape_string($link, $registrar_filter) . "%'";
}

$where_clause = !empty($where) ? " WHERE " . implode(' AND ', $where) : "";
$sql = "SELECT * FROM dominios2020 $where_clause ORDER BY expiration ASC";
$result = mysqli_query($link, $sql);

// Obtener opciones para filtros
$types = [];
$registrars = [];
$res = mysqli_query($link, "SELECT DISTINCT type FROM dominios2020 ORDER BY type");
while ($row = mysqli_fetch_assoc($res)) $types[] = $row['type'];
$res = mysqli_query($link, "SELECT DISTINCT registrar FROM dominios2020 WHERE registrar IS NOT NULL ORDER BY registrar");
while ($row = mysqli_fetch_assoc($res)) $registrars[] = $row['registrar'];
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Control de Dominios</title>
    <!-- Bootstrap 4.6.x -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        body {
            padding-top: 70px;
            padding-bottom: 60px;
            background-color: #f8f9fa;
            color: #333;
        }
        .navbar {
            background-color: #2c3e50;
        }
        .navbar-brand, .navbar-nav .nav-link {
            color: #ecf0f1 !important;
        }
        .footer {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px 0;
            text-align: center;
            position: fixed;
            bottom: 0;
            width: 100%;
        }
        .table {
            background-color: white;
        }
        .table tr.yellow { background-color: #fff3cd; }
        .table tr.red { background-color: #f8d7da; }
        .table tr.green { background-color: #d4edda; }
        .btn-update {
            font-size: 0.85em;
            padding: 0.25rem 0.5rem;
        }
        .btn-site {
            font-size: 0.85em;
            padding: 0.25rem 0.5rem;
        }
        .filter-container {
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .text-small {
            font-size: 0.9em;
            color: #666;
        }
    </style>
</head>
<body>
    <!-- Barra de Navegación Fija -->
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
        <div class="container">
            <a class="navbar-brand" href="#">Control de Dominios</a>
            <div class="navbar-nav ml-auto">
                <a class="nav-link" href="https://google.com" target="_blank">
                    <i class="fas fa-external-link-alt"></i> Google
                </a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h2 class="mb-4">Gestión de Dominios</h2>

        <!-- Filtros -->
        <div class="filter-container">
            <form method="GET" class="row">
                <div class="col-md-3">
                    <label>Extensión</label>
                    <select name="ext" class="form-control">
                        <option value="">Todas</option>
                        <option value=".com" <?= $extension_filter=='.com'?'selected':'' ?>>.com</option>
                        <option value=".net" <?= $extension_filter=='.net'?'selected':'' ?>>.net</option>
                        <option value=".org" <?= $extension_filter=='.org'?'selected':'' ?>>.org</option>
                        <option value=".info" <?= $extension_filter=='.info'?'selected':'' ?>>.info</option>
                        <option value=".xyz" <?= $extension_filter=='.xyz'?'selected':'' ?>>.xyz</option>
                        <option value=".vip" <?= $extension_filter=='.vip'?'selected':'' ?>>.vip</option>
                        <option value=".monster" <?= $extension_filter=='.monster'?'selected':'' ?>>.monster</option>
                        <option value=".mom" <?= $extension_filter=='.mom'?'selected':'' ?>>.mom</option>
                        <option value=".mx" <?= $extension_filter=='.mx'?'selected':'' ?>>.mx</option>
                        <option value=".com.mx" <?= $extension_filter=='.com.mx'?'selected':'' ?>>.com.mx</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <label>Cliente</label>
                    <select name="customer" class="form-control">
                        <option value="">Todos</option>
                        <option value="YES" <?= $customer_filter=='YES'?'selected':'' ?>>Sí</option>
                        <option value="NO" <?= $customer_filter=='NO'?'selected':'' ?>>No</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <label>Tipo</label>
                    <select name="type" class="form-control">
                        <option value="">Todos</option>
                        <?php foreach ($types as $t): ?>
                            <option value="<?= htmlspecialchars($t) ?>" <?= $type_filter==$t?'selected':'' ?>>
                                <?= htmlspecialchars($t) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3">
                    <label>Registrar</label>
                    <select name="registrar" class="form-control">
                        <option value="">Todos</option>
                        <?php foreach ($registrars as $r): ?>
                            <option value="<?= htmlspecialchars($r) ?>" <?= $registrar_filter==$r?'selected':'' ?>>
                                <?= htmlspecialchars($r) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-12 mt-2">
                    <button type="submit" class="btn btn-primary btn-sm">Filtrar</button>
                    <a href="?" class="btn btn-secondary btn-sm">Limpiar</a>
                </div>
            </form>
        </div>

        <!-- Tabla de Dominios -->
        <div class="table">
            <table class="table table-bordered table-striped">
                <thead class="thead-dark">
                    <tr>
                        <th>Nombre</th>
                        <th>Servidores</th>
                        <th>Registro</th>
                        <th>Expira</th>
                        <th>Días Restantes</th>
                        <th>Registrar</th>
                        <th>Tipo</th>
                        <th>Cliente</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($row = mysqli_fetch_assoc($result)): 
                        $today = new DateTime();
                        $exp_date = $row['expiration'] ? new DateTime($row['expiration']) : null;
                        $diff_days = $exp_date ? $today->diff($exp_date)->days : 9999;
                        $is_past = $exp_date && $exp_date < $today;

                        $row_class = '';
                        if ($is_past) {
                            $row_class = 'red';
                        } else {
                            if ($diff_days < 14) {
                                $row_class = 'red';
                            } elseif ($diff_days < 60) {
                                $row_class = 'yellow';
                            } elseif ($diff_days > 370) {
                                $row_class = 'green';
                            }
                        }
                    ?>
                    <tr class="<?= $row_class ?>">
                        <td>
                            <a href="https://<?= htmlspecialchars($row['dominio']) ?>" target="_blank" class="btn btn-link btn-site p-0">
                                <i class="fas fa-globe"></i> <?= htmlspecialchars($row['dominio']) ?>
                            </a>
                        </td>
                        <td class="text-small"><?= htmlspecialchars($row['servidores']) ?></td>
                        <td><?= $row['registered'] ? htmlspecialchars($row['registered']) : 'N/A' ?></td>
                        <td><?= $row['expiration'] ? htmlspecialchars($row['expiration']) : 'N/A' ?></td>
                        <td>
                            <?php if ($is_past): ?>
                                <span class="text-danger">Vencido (<?= $diff_days ?> días)</span>
                            <?php else: ?>
                                <?= $diff_days ?> días
                            <?php endif; ?>
                        </td>
                        <td><?= htmlspecialchars($row['registrar']) ?></td>
                        <td><?= htmlspecialchars($row['type']) ?></td>
                        <td><?= $row['iscustomer'] == 'YES' ? '<span class="text-success">Sí</span>' : 'No' ?></td>
                        <td>
                            <a href="?update=<?= urlencode($row['dominio']) ?>" class="btn btn-warning btn-sm btn-update">
                                <i class="fas fa-sync"></i> Actualizar WHOIS
                            </a>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Footer Fijo -->
    <div class="footer">
        <div>Control de Dominios v1.0 | Modelo: Single-File PHP 8.x + Bootstrap 4.6 | <span id="clock"></span></div>
    </div>

    <script>
        // Reloj en tiempo real
        function updateClock() {
            const now = new Date();
            document.getElementById('clock').textContent = now.toLocaleString();
        }
        setInterval(updateClock, 1000);
        updateClock();
    </script>
</body>
</html>