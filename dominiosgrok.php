<?php
include 'config.php'; // Asumiendo que establece $link = mysqli_connect(...);

// Función para consultar WHOIS para dominios genéricos (.com, .net, etc.)
function whois_generic($domain) {
    $server = '';
    $tld = strtolower(pathinfo($domain, PATHINFO_EXTENSION));
    switch ($tld) {
        case 'com':
        case 'net':
            $server = 'whois.verisign-grs.com';
            break;
        case 'org':
            $server = 'whois.pir.org';
            break;
        case 'info':
            $server = 'whois.afilias.net';
            break;
        case 'monster':
        case 'xyz':
        case 'vip':
        case 'mom':
            $server = 'whois.nic.xyz'; // Ajustar según TLD específico; asumir genérico para simplicidad
            break;
        default:
            return false;
    }

    $socket = fsockopen($server, 43, $errno, $errstr, 10);
    if (!$socket) {
        return false;
    }
    fputs($socket, $domain . "\r\n");
    $response = '';
    while (!feof($socket)) {
        $response .= fgets($socket, 128);
    }
    fclose($socket);
    return $response;
}

// Función para consultar WHOIS para .mx y .com.mx
function whois_mx($domain) {
    $server = 'whois.mx';
    $socket = fsockopen($server, 43, $errno, $errstr, 10);
    if (!$socket) {
        return false;
    }
    fputs($socket, $domain . "\r\n");
    $response = '';
    while (!feof($socket)) {
        $response .= fgets($socket, 128);
    }
    fclose($socket);
    return $response;
}

// Función para parsear WHOIS genérico
function parse_whois_generic($whois) {
    $data = [
        'nameservers' => [],
        'registered' => null,
        'expiration' => null,
        'registrar' => null
    ];

    $lines = explode("\n", $whois);
    foreach ($lines as $line) {
        if (stripos($line, 'Name Server:') !== false) {
            $data['nameservers'][] = trim(substr($line, strpos($line, ':') + 1));
        } elseif (stripos($line, 'Creation Date:') !== false) {
            $data['registered'] = date('Y-m-d', strtotime(trim(substr($line, strpos($line, ':') + 1))));
        } elseif (stripos($line, 'Registry Expiry Date:') !== false || stripos($line, 'Expiration Date:') !== false) {
            $data['expiration'] = date('Y-m-d', strtotime(trim(substr($line, strpos($line, ':') + 1))));
        } elseif (stripos($line, 'Registrar:') !== false) {
            $data['registrar'] = trim(substr($line, strpos($line, ':') + 1));
        }
    }
    return $data;
}

// Función para parsear WHOIS .mx
function parse_whois_mx($whois) {
    $data = [
        'nameservers' => [],
        'registered' => null,
        'expiration' => null,
        'registrar' => null
    ];

    $lines = explode("\n", $whois);
    foreach ($lines as $line) {
        if (stripos($line, 'NameServers:') !== false) {
            // Continuar recolectando nameservers en líneas siguientes
            continue;
        } elseif (preg_match('/DNS:\s+(.+)/i', $line, $matches)) {
            $data['nameservers'][] = trim($matches[1]);
        } elseif (stripos($line, 'Created On:') !== false) {
            $data['registered'] = date('Y-m-d', strtotime(trim(substr($line, strpos($line, ':') + 1))));
        } elseif (stripos($line, 'Expiration:') !== false) {
            $data['expiration'] = date('Y-m-d', strtotime(trim(substr($line, strpos($line, ':') + 1))));
        } elseif (stripos($line, 'Registrar:') !== false) {
            $data['registrar'] = trim(substr($line, strpos($line, ':') + 1));
        }
    }
    return $data;
}

// Manejar acción de actualización
if (isset($_GET['action']) && $_GET['action'] === 'update' && isset($_GET['dominio'])) {
    $dominio = mysqli_real_escape_string($link, $_GET['dominio']);
    $tld = strtolower(pathinfo($dominio, PATHINFO_EXTENSION));

    if (in_array($tld, ['mx', 'com.mx'])) {
        $whois = whois_mx($dominio);
        $parsed = parse_whois_mx($whois);
    } else {
        $whois = whois_generic($dominio);
        $parsed = parse_whois_generic($whois);
    }

    if ($parsed) {
        $servidores = implode(',', $parsed['nameservers']);
        $registered = $parsed['registered'] ? "'{$parsed['registered']}'" : 'NULL';
        $expiration = $parsed['expiration'] ? "'{$parsed['expiration']}'" : 'NULL';
        $registrar = mysqli_real_escape_string($link, $parsed['registrar'] ?? '');
        $last_updated = date('Y-m-d');

        $sql = "UPDATE dominios2020 SET 
                servidores = '$servidores',
                registered = $registered,
                expiration = $expiration,
                registrar = '$registrar',
                last_updated = '$last_updated'
                WHERE dominio = '$dominio'";
        mysqli_query($link, $sql);
    }
    // Redirigir para evitar reenvío
    header('Location: ' . basename(__FILE__));
    exit;
}

// Obtener filtros
$filter_ext = isset($_GET['ext']) ? mysqli_real_escape_string($link, $_GET['ext']) : '';
$filter_type = isset($_GET['type']) ? mysqli_real_escape_string($link, $_GET['type']) : '';
$filter_iscustomer = isset($_GET['iscustomer']) ? mysqli_real_escape_string($link, $_GET['iscustomer']) : '';
$filter_registrar = isset($_GET['registrar']) ? mysqli_real_escape_string($link, $_GET['registrar']) : '';

// Construir query
$sql = "SELECT * FROM dominios2020 WHERE showit = 'YES'";
if ($filter_ext) {
    $sql .= " AND dominio LIKE '%.$filter_ext'";
}
if ($filter_type) {
    $sql .= " AND type = '$filter_type'";
}
if ($filter_iscustomer) {
    $sql .= " AND iscustomer = '$filter_iscustomer'";
}
if ($filter_registrar) {
    $sql .= " AND registrar = '$filter_registrar'";
}
$sql .= " ORDER BY expiration ASC";
$result = mysqli_query($link, $sql);

// Obtener listas únicas para filtros (para selects)
$extensions = ['com', 'net', 'org', 'info', 'monster', 'xyz', 'vip', 'mom', 'mx', 'com.mx'];
$types = []; // Asumir que se obtienen de DB si es necesario, o dejar input
$iscustomers = ['YES', 'NO'];
$registrars = []; // Similar, obtener únicos de DB
$res_types = mysqli_query($link, "SELECT DISTINCT type FROM dominios2020");
while ($row = mysqli_fetch_assoc($res_types)) $types[] = $row['type'];
$res_reg = mysqli_query($link, "SELECT DISTINCT registrar FROM dominios2020");
while ($row = mysqli_fetch_assoc($res_reg)) $registrars[] = $row['registrar'];

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Control de Dominios</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        body { padding-top: 56px; padding-bottom: 56px; background-color: #f8f9fa; }
        .navbar { background-color: #343a40; }
        .footer { background-color: #343a40; color: white; }
        .table th { background-color: #6c757d; color: white; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
        <a class="navbar-brand" href="#">Control de Dominios</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item"><a class="nav-link" href="https://google.com">Google</a></li>
            </ul>
            <span class="navbar-text">Grok 4 by xAI</span>
        </div>
    </nav>

    <div class="container mt-4">
        <h1 class="text-center mb-4">Lista de Dominios</h1>

        <!-- Formulario de filtros -->
        <form method="GET" class="mb-4">
            <div class="row">
                <div class="col-md-3">
                    <label>Extensión</label>
                    <select name="ext" class="form-control">
                        <option value="">Todas</option>
                        <?php foreach ($extensions as $ext): ?>
                            <option value="<?php echo $ext; ?>" <?php echo $filter_ext == $ext ? 'selected' : ''; ?>><?php echo $ext; ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3">
                    <label>Type</label>
                    <select name="type" class="form-control">
                        <option value="">Todos</option>
                        <?php foreach ($types as $t): ?>
                            <option value="<?php echo $t; ?>" <?php echo $filter_type == $t ? 'selected' : ''; ?>><?php echo $t; ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3">
                    <label>Is Customer</label>
                    <select name="iscustomer" class="form-control">
                        <option value="">Todos</option>
                        <?php foreach ($iscustomers as $ic): ?>
                            <option value="<?php echo $ic; ?>" <?php echo $filter_iscustomer == $ic ? 'selected' : ''; ?>><?php echo $ic; ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3">
                    <label>Registrar</label>
                    <select name="registrar" class="form-control">
                        <option value="">Todos</option>
                        <?php foreach ($registrars as $r): ?>
                            <option value="<?php echo $r; ?>" <?php echo $filter_registrar == $r ? 'selected' : ''; ?>><?php echo $r; ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <button type="submit" class="btn btn-primary mt-2">Filtrar</button>
        </form>

        <!-- Tabla de dominios -->
        <table class="table table-bordered table-hover">
            <thead>
                <tr>
                    <th>Dominio</th>
                    <th>Servidores</th>
                    <th>Registrado</th>
                    <th>Expiración</th>
                    <th>Días Restantes</th>
                    <th>Registrar</th>
                    <th>Type</th>
                    <th>Is Customer</th>
                    <th>Nota</th>
                    <th>Última Actualización</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($row = mysqli_fetch_assoc($result)): ?>
                    <?php
                    $expiration = new DateTime($row['expiration']);
                    $today = new DateTime();
                    $days_left = $today->diff($expiration)->days;
                    if ($expiration < $today) $days_left = -$days_left; // Si expirado, negativo
                    $bg_class = 'bg-white';
                    if ($days_left < 14) $bg_class = 'bg-danger text-white';
                    elseif ($days_left < 60) $bg_class = 'bg-warning';
                    elseif ($days_left > 370) $bg_class = 'bg-success text-white';
                    ?>
                    <tr class="<?php echo $bg_class; ?>">
                        <td><a href="http://<?php echo $row['dominio']; ?>" target="_blank"><?php echo $row['dominio']; ?></a></td>
                        <td><?php echo $row['servidores']; ?></td>
                        <td><?php echo $row['registered']; ?></td>
                        <td><?php echo $row['expiration']; ?></td>
                        <td><?php echo $days_left; ?></td>
                        <td><?php echo $row['registrar']; ?></td>
                        <td><?php echo $row['type']; ?></td>
                        <td><?php echo $row['iscustomer']; ?></td>
                        <td><?php echo $row['NOTA']; ?></td>
                        <td><?php echo $row['last_updated']; ?></td>
                        <td>
                            <a href="?action=update&dominio=<?php echo $row['dominio']; ?>" class="btn btn-sm btn-info"><i class="fas fa-sync-alt"></i> Actualizar</a>
                        </td>
                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>

    <footer class="footer fixed-bottom text-center py-2">
        &copy; <?php echo date('Y'); ?> Control de Dominios - Desarrollado con PHP 8.x
    </footer>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>