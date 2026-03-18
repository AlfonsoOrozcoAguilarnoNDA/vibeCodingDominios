<?php
// index.php
require_once("config.php"); // $link ya definido

// Función para calcular días restantes
function dias_restantes($exp) {
    if (!$exp) return null;
    $hoy = new DateTime();
    $expDate = new DateTime($exp);
    return $hoy->diff($expDate)->days * ($expDate >= $hoy ? 1 : -1);
}

// Filtros
$where = [];
if (!empty($_GET['ext'])) {
    $ext = mysqli_real_escape_string($link, $_GET['ext']);
    $where[] = "dominio LIKE '%$ext'";
}
if (!empty($_GET['type'])) {
    $type = mysqli_real_escape_string($link, $_GET['type']);
    $where[] = "type='$type'";
}
if (!empty($_GET['iscustomer'])) {
    $iscustomer = mysqli_real_escape_string($link, $_GET['iscustomer']);
    $where[] = "iscustomer='$iscustomer'";
}
if (!empty($_GET['registrar'])) {
    $registrar = mysqli_real_escape_string($link, $_GET['registrar']);
    $where[] = "registrar='$registrar'";
}
$whereSQL = $where ? "WHERE " . implode(" AND ", $where) : "";

// Actualizar WHOIS simulado (ejemplo)
if (isset($_GET['update'])) {
    $dom = mysqli_real_escape_string($link, $_GET['update']);
    // Aquí iría la lógica real de WHOIS, se simula actualización
    $today = date("Y-m-d");
    mysqli_query($link, "UPDATE dominios2020 SET last_updated='$today' WHERE dominio='$dom'");
    header("Location: index.php");
    exit;
}

// Consulta
$sql = "SELECT * FROM dominios2020 $whereSQL ORDER BY expiration ASC";
$res = mysqli_query($link, $sql);
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Control de Dominios</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.6.2/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
<style>
body { padding-top:70px; padding-bottom:70px; }
.navbar, footer { background:#343a40; color:white; }
.table-hover tbody tr:hover { background-color:#f5f5f5; }
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg fixed-top">
  <a class="navbar-brand text-white" href="https://www.google.com" target="_blank">Google</a>
  <span class="ml-auto text-white">Modelo: PHP 8.x + Bootstrap 4.6.x</span>
</nav>

<div class="container">
  <h3 class="mb-4">Listado de Dominios</h3>
  <table class="table table-bordered table-hover">
    <thead class="thead-dark">
      <tr>
        <th>Dominio</th>
        <th>Servidores</th>
        <th>Registrado</th>
        <th>Expira</th>
        <th>Días Restantes</th>
        <th>Registrar</th>
        <th>Cliente</th>
        <th>Tipo</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody>
      <?php while($row = mysqli_fetch_assoc($res)): 
        $dias = dias_restantes($row['expiration']);
        $color = "";
        if ($dias !== null) {
            if ($dias < 14) $color = "table-danger";
            elseif ($dias < 60) $color = "table-warning";
            elseif ($dias > 370) $color = "table-success";
        }
      ?>
      <tr class="<?= $color ?>">
        <td><a href="http://<?= htmlspecialchars($row['dominio']) ?>" target="_blank"><?= htmlspecialchars($row['dominio']) ?></a></td>
        <td><?= htmlspecialchars($row['servidores']) ?></td>
        <td><?= htmlspecialchars($row['registered']) ?></td>
        <td><?= htmlspecialchars($row['expiration']) ?></td>
        <td><?= $dias !== null ? $dias : "-" ?></td>
        <td><?= htmlspecialchars($row['registrar']) ?></td>
        <td><?= htmlspecialchars($row['iscustomer']) ?></td>
        <td><?= htmlspecialchars($row['type']) ?></td>
        <td>
          <a href="?update=<?= urlencode($row['dominio']) ?>" class="btn btn-sm btn-info">
            <i class="fas fa-sync-alt"></i> WHOIS
          </a>
        </td>
      </tr>
      <?php endwhile; ?>
    </tbody>
  </table>
</div>

<footer class="fixed-bottom text-center py-2">
  <small>&copy; <?= date("Y") ?> Control de Dominios - Estilo sobrio y profesional</small>
</footer>
</body>
</html>
