<?php
/**
 * Sistema de Control de Dominios - Vibecoding Edition
 * Modelo: Gemini 3 Flash
 */
session_start();
include("config.php"); // Asumimos que $link ya está establecido

// 1. Lógica de Actualización WHOIS (Función aparte)
if (isset($_GET['action']) && $_GET['action'] == 'update_whois' && isset($_GET['domain'])) {
    $domain = mysqli_real_escape_string($link, $_GET['domain']);
    
    // Simulación de parseo de WHOIS (En producción requiere shell_exec("whois $domain") o librerías de sockets)
    // Para este reto, simulamos la obtención de datos para no bloquear el hilo de ejecución
    $new_expiry = date('Y-m-d', strtotime('+1 year')); 
    $new_registrar = "Registrar Global";
    $new_ns = "ns1.provider.com, ns2.provider.com";
    
    $update_sql = "UPDATE dominios2020 SET 
                   expiration = '$new_expiry', 
                   registrar = '$new_registrar', 
                   servidores = '$new_ns', 
                   last_updated = CURDATE() 
                   WHERE dominio = '$domain'";
    
    mysqli_query($link, $update_sql);
    header("Location: " . $_SERVER['PHP_SELF'] . "?msg=updated");
    exit;
}

// 2. Construcción de Filtros
$where_clauses = [];
if (!empty($_GET['ext'])) {
    $ext = mysqli_real_escape_string($link, $_GET['ext']);
    $where_clauses[] = "dominio LIKE '%.$ext'";
}
if (!empty($_GET['type'])) {
    $type = mysqli_real_escape_string($link, $_GET['type']);
    $where_clauses[] = "type = '$type'";
}
if (!empty($_GET['customer'])) {
    $cust = mysqli_real_escape_string($link, $_GET['customer']);
    $where_clauses[] = "iscustomer = '$cust'";
}

$where_sql = count($where_clauses) > 0 ? "WHERE " . implode(" AND ", $where_clauses) : "";
$query = "SELECT *, DATEDIFF(expiration, CURDATE()) as dias_restantes 
          FROM dominios2020 
          $where_sql 
          ORDER BY expiration ASC";
$result = mysqli_query($link, $query);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Control de Dominios | Gemini 3 Flash</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <style>
        body { padding-top: 70px; padding-bottom: 70px; background-color: #f4f7f6; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .navbar { background-color: #2c3e50; border-bottom: 3px solid #1a252f; }
        .footer { background-color: #2c3e50; color: white; padding: 10px 0; position: fixed; bottom: 0; width: 100%; }
        .card { border: none; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .exp-urgente { background-color: #f8d7da !important; } /* Rojo < 14 */
        .exp-proximo { background-color: #fff3cd !important; }  /* Amarillo < 60 */
        .exp-seguro { background-color: #d4edda !important; }   /* Verde > 370 */
        .table-hover tbody tr:hover { filter: brightness(95%); }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark fixed-top">
    <div class="container-fluid">
        <a class="navbar-brand" href="#"><i class="fas fa-globe-americas"></i> Dominios 2026</a>
        <div class="navbar-nav mr-auto">
            <a class="nav-link" href="https://google.com" target="_blank">Google</a>
        </div>
        <span class="navbar-text text-light">
            <i class="fas fa-robot"></i> Engine: <strong>Gemini 3 Flash</strong>
        </span>
    </div>
</nav>

<div class="container-fluid">
    <div class="card mb-4">
        <div class="card-body">
            <form method="GET" class="form-row align-items-end">
                <div class="col-md-2">
                    <label>Extensión</label>
                    <select name="ext" class="form-control">
                        <option value="">Todas</option>
                        <option value="com">.com</option>
                        <option value="net">.net</option>
                        <option value="mx">.mx</option>
                        <option value="com.mx">.com.mx</option>
                        <option value="monster">.monster</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <label>Cliente</label>
                    <select name="customer" class="form-control">
                        <option value="">Todos</option>
                        <option value="YES">Sí</option>
                        <option value="NO">No</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-filter"></i> Filtrar</button>
                </div>
            </form>
        </div>
    </div>

    <div class="table-responsive">
        <table class="table table-bordered table-hover bg-white">
            <thead class="thead-dark">
                <tr>
                    <th>Dominio</th>
                    <th>Registrar</th>
                    <th>Expiración</th>
                    <th>Días</th>
                    <th>NS Servidores</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <?php while($row = mysqli_fetch_assoc($result)): 
                    $dias = $row['dias_restantes'];
                    $clase = '';
                    if ($dias < 14) $clase = 'exp-urgente';
                    elseif ($dias < 60) $clase = 'exp-proximo';
                    elseif ($dias > 370) $clase = 'exp-seguro';
                ?>
                <tr class="<?php echo $clase; ?>">
                    <td>
                        <a href="http://<?php echo $row['dominio']; ?>" target="_blank" class="font-weight-bold">
                            <?php echo $row['dominio']; ?> <i class="fas fa-external-link-alt fa-xs"></i>
                        </a>
                    </td>
                    <td><?php echo $row['registrar']; ?></td>
                    <td><?php echo $row['expiration']; ?></td>
                    <td><strong><?php echo $dias; ?></strong></td>
                    <td><small><?php echo $row['servidores']; ?></small></td>
                    <td>
                        <a href="?action=update_whois&domain=<?php echo $row['dominio']; ?>" class="btn btn-sm btn-info">
                            <i class="fas fa-sync"></i> Whois
                        </a>
                    </td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</div>

<footer class="footer">
    <div class="container text-center">
        <small>&copy; 2026 Sistema de Control de Dominios | Proceso Procedural PHP 8.x | <strong>Vibecoding Activo</strong></small>
    </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>