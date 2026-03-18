<?php
/*
    dominiosminimaxhumano.php - Control de Dominios y Expiraciones
    
    Copyright (C) 2026 Alfonso Orozco Aguilar (vibecodingmexico.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; version 2.1 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software Foundation,
    Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    ============================================================================
    CRÉDITOS
    ============================================================================
    Lógica WHOIS:       Alfonso Orozco Aguilar (versión humana)
    Apariencia visual:  Estándar MiniMax-M2.5 (vibecodingmexico.com)
    Altas y bajas:      MiniMax-M2.5
    Integración:        Claude Sonnet 4.6 (claude-sonnet-4-6)
    Fecha:              15 de marzo de 2026
    Experimento:        https://vibecodingmexico.com/vibecoding-control-de-dominios/

    Stack: PHP 8.x Procedural, Bootstrap 4.6.2, Font Awesome 5.15.4
    Asume config.php con $link (mysqli procedural)
*/

// Headers anti-caché
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

session_start();
include_once 'config.php';
global $link;

// ============================================================
// FUNCIONES AUXILIARES (versión humana)
// ============================================================

function left($str, $length) {
    return substr($str, 0, $length);
}

function right($str, $length) {
    return substr($str, -$length);
}

function aValues319($Qx) {
    global $link;
    $rsX = mysqli_query($link, $Qx) or mysqli_error($link);
    $Qx2 = strtolower($Qx);
    if (left($Qx2, 6) <> 'select') return "";
    $aDataX = array();
    $rows = mysqli_num_rows($rsX);
    if ($rows == 0) return array("", "");
    $Campos = mysqli_num_fields($rsX);
    while ($regX = mysqli_fetch_array($rsX)) {
        for ($iX = 0; $iX < $Campos; $iX++) {
            $finfo = mysqli_fetch_field_direct($rsX, $iX);
            $name = $finfo->name;
            $aDataX[] = $regX[$name];
        }
    }
    return $aDataX;
}

// ============================================================
// WHOIS GENERAL (.com .net .org .info .vip etc.)
// ============================================================

function obtenerInfoDominio($dominio) {
    global $link;
    $dominio = strtolower(trim($dominio));

    if (!filter_var($dominio, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return "||Error: Dominio inválido||||||||";
    }

    $extension = substr($dominio, strrpos($dominio, '.'));

    $servidoresWhois = [
        '.com'    => 'whois.verisign-grs.com',
        '.net'    => 'whois.verisign-grs.com',
        '.org'    => 'whois.pir.org',
        '.info'   => 'whois.afilias.net',
        '.vip'    => 'whois.nic.vip',
        '.monster'=> 'whois.centralreg.com',
        '.xyz'    => 'whois.nic.xyz',
        '.mom'    => 'whois.nic.mom',
        '.mx'     => 'whois.mx',
        '.com.mx' => 'whois.mx'
    ];

    if (!isset($servidoresWhois[$extension])) {
        return "||Error: Extensión no soportada: $extension||||||||";
    }

    $datosWhois = consultarWhois($dominio, $servidoresWhois[$extension]);
    if (!$datosWhois) {
        return "||Error: No se pudo obtener información WHOIS||||||||";
    }

    $info = parsearDatosWhois($datosWhois, $extension);
    $info['registrar'] = trim($info['registrar']);

    $servidores  = ($info['ns1'] ?? '') . ',' . ($info['ns2'] ?? '');
    $sql = "UPDATE dominios2020 SET 
                servidores='" . mysqli_real_escape_string($link, $servidores) . "',
                registered='" . mysqli_real_escape_string($link, $info['fechaCreacion']) . "',
                expiration='" . mysqli_real_escape_string($link, $info['fechaExpira']) . "',
                registrar='"  . mysqli_real_escape_string($link, $info['registrar']) . "',
                last_updated=now()
            WHERE dominio='" . mysqli_real_escape_string($link, $dominio) . "'";
    mysqli_query($link, $sql);

    return sprintf("||%s|%s|%s|%s|%s|%s|%s||",
        $dominio,
        $info['registrar']        ?? '',
        $info['fechaCreacion']    ?? '',
        $info['fechaUltimoCambio']?? '',
        $info['fechaExpira']      ?? '',
        $info['ns1']              ?? '',
        $info['ns2']              ?? ''
    );
}

function consultarWhois($dominio, $servidor, $puerto = 43) {
    $socket = @fsockopen($servidor, $puerto, $errno, $errstr, 10);
    if (!$socket) return false;
    fwrite($socket, $dominio . "\r\n");
    $respuesta = '';
    while (!feof($socket)) {
        $respuesta .= fgets($socket, 1024);
    }
    fclose($socket);
    return $respuesta;
}

function parsearDatosWhois($datos, $extension) {
    $info = ['registrar'=>'','fechaCreacion'=>'','fechaUltimoCambio'=>'','fechaExpira'=>'','ns1'=>'','ns2'=>''];
    $lineas = explode("\n", $datos);
    $nameservers = [];

    foreach ($lineas as $linea) {
        $linea = trim($linea);

        if ($extension === '.com.mx') {
            if (preg_match('/^Created On:\s*(.+)$/i',      $linea, $m)) $info['fechaCreacion']     = formatearFecha($m[1]);
            elseif (preg_match('/^Last Updated On:\s*(.+)$/i', $linea, $m) && empty($info['fechaUltimoCambio'])) $info['fechaUltimoCambio'] = formatearFecha($m[1]);
            elseif (preg_match('/^Expiration Date:\s*(.+)$/i', $linea, $m)) $info['fechaExpira']   = formatearFecha($m[1]);
            elseif (preg_match('/^Changed:\s*(.+)$/i',         $linea, $m) && empty($info['fechaUltimoCambio'])) $info['fechaUltimoCambio'] = formatearFecha($m[1]);
            elseif (preg_match('/^Registrar:\s*(.+)$/i',       $linea, $m)) $info['registrar']     = trim($m[1]);
            elseif (preg_match('/^URL:\s*(.+)$/i',             $linea, $m) && empty($info['registrar'])) $info['registrar'] = trim($m[1]);
            elseif (preg_match('/^DNS:\s*(.+)$/i',             $linea, $m)) $nameservers[] = strtolower(trim($m[1]));
        } else {
            if (preg_match('/^Registrar:\s*(.+)$/i',                               $linea, $m)) $info['registrar'] = trim($m[1]);
            elseif (preg_match('/^Sponsoring Registrar:\s*(.+)$/i',                $linea, $m) && empty($info['registrar'])) $info['registrar'] = trim($m[1]);
            elseif (preg_match('/^Creation Date:\s*(.+)$/i',                       $linea, $m)) $info['fechaCreacion'] = formatearFecha($m[1]);
            elseif (preg_match('/^Created On:\s*(.+)$/i',                          $linea, $m) && empty($info['fechaCreacion'])) $info['fechaCreacion'] = formatearFecha($m[1]);
            elseif (preg_match('/^Updated Date:\s*(.+)$/i',                        $linea, $m)) $info['fechaUltimoCambio'] = formatearFecha($m[1]);
            elseif (preg_match('/^Last Updated On:\s*(.+)$/i',                     $linea, $m) && empty($info['fechaUltimoCambio'])) $info['fechaUltimoCambio'] = formatearFecha($m[1]);
            elseif (preg_match('/^Registry Expiry Date:\s*(.+)$/i',                $linea, $m)) $info['fechaExpira'] = formatearFecha($m[1]);
            elseif (preg_match('/^Registrar Registration Expiration Date:\s*(.+)$/i',$linea,$m) && empty($info['fechaExpira'])) $info['fechaExpira'] = formatearFecha($m[1]);
            elseif (preg_match('/^Expir(?:y|ation) Date:\s*(.+)$/i',               $linea, $m) && empty($info['fechaExpira'])) $info['fechaExpira'] = formatearFecha($m[1]);
            elseif (preg_match('/^Expires.*:\s*(.+)$/i',                            $linea, $m) && empty($info['fechaExpira'])) $info['fechaExpira'] = formatearFecha($m[1]);
            elseif (preg_match('/^Name Server:\s*(.+)$/i',                          $linea, $m)) $nameservers[] = strtolower(trim($m[1]));
            elseif (preg_match('/^nserver:\s*(.+)$/i',                              $linea, $m)) $nameservers[] = strtolower(trim($m[1]));
        }
    }

    if (count($nameservers) > 0) $info['ns1'] = $nameservers[0];
    if (count($nameservers) > 1) $info['ns2'] = $nameservers[1];
    return $info;
}

function formatearFecha($fecha) {
    $fecha = trim($fecha);
    $fecha = preg_replace('/\s+/', ' ', $fecha);

    $formatos = [
        'Y-m-d\TH:i:s\Z', 'Y-m-d\TH:i:s.u\Z', 'Y-m-d H:i:s \U\T\C',
        'Y-m-d H:i:s', 'Y-m-d', 'd-M-Y', 'M d Y', 'd/m/Y', 'm/d/Y',
        'Y/m/d', 'D M d H:i:s Y', 'D, d M Y H:i:s \U\T\C',
        'Y-m-d\TH:i:s', 'd-m-Y',
    ];

    foreach ($formatos as $formato) {
        $fechaObj = DateTime::createFromFormat($formato, $fecha);
        if ($fechaObj !== false) return $fechaObj->format('Y-m-d');
    }

    $timestamp = strtotime($fecha);
    if ($timestamp !== false) return date('Y-m-d', $timestamp);
    return $fecha;
}

// ============================================================
// WHOIS ESPECIAL .mx y .com.mx (versión humana)
// ============================================================

function obtenerInfoDominioMX($dominio) {
    global $link;
    $dominio = strtolower(trim($dominio));

    if (!preg_match('/\.(mx|com\.mx)$/i', $dominio)) {
        return "||Error: Solo para .mx y .com.mx||||||||";
    }

    $datosWhois = consultarWhoisMX($dominio);
    if (!$datosWhois) {
        return "||Error: No se pudo conectar a whois.mx||||||||";
    }

    $info = parsearDatosMX($datosWhois);
    $info['registrar'] = trim($info['registrar']);

    $servidores = ($info['ns1'] ?? '') . ',' . ($info['ns2'] ?? '');
    $sql = "UPDATE dominios2020 SET 
                servidores='" . mysqli_real_escape_string($link, $servidores) . "',
                registered='" . mysqli_real_escape_string($link, $info['fechaCreacion']) . "',
                expiration='" . mysqli_real_escape_string($link, $info['fechaExpira']) . "',
                registrar='"  . mysqli_real_escape_string($link, $info['registrar']) . "',
                last_updated=now()
            WHERE dominio='" . mysqli_real_escape_string($link, $dominio) . "'";
    mysqli_query($link, $sql);

    return sprintf("||%s|%s|%s|%s|%s|%s|%s||",
        $dominio,
        $info['registrar']        ?? '',
        $info['fechaCreacion']    ?? '',
        $info['fechaUltimoCambio']?? '',
        $info['fechaExpira']      ?? '',
        $info['ns1']              ?? '',
        $info['ns2']              ?? ''
    );
}

function consultarWhoisMX($dominio) {
    $servidor  = 'whois.mx';
    $puerto    = 43;
    $timeout   = 15;
    $errno = 0; $errstr = '';

    $socket = @fsockopen($servidor, $puerto, $errno, $errstr, $timeout);
    if (!$socket) {
        $ip = gethostbyname($servidor);
        if ($ip !== $servidor) {
            $socket = @fsockopen($ip, $puerto, $errno, $errstr, $timeout);
        }
        if (!$socket) return false;
    }

    stream_set_timeout($socket, $timeout);
    fwrite($socket, $dominio . "\r\n");

    $respuesta  = '';
    $start_time = time();
    while (!feof($socket) && (time() - $start_time) < $timeout) {
        $line = fgets($socket, 1024);
        if ($line === false) break;
        $respuesta .= $line;
    }
    fclose($socket);

    // Convertir encoding ISO-8859-1 → UTF-8 (NIC México)
    if (function_exists('mb_detect_encoding')) {
        $encoding = mb_detect_encoding($respuesta, ['UTF-8', 'ISO-8859-1', 'ASCII']);
        if ($encoding && $encoding !== 'UTF-8') {
            $respuesta = mb_convert_encoding($respuesta, 'UTF-8', $encoding);
        }
    }

    return $respuesta;
}

function parsearDatosMX($datos) {
    $info = ['registrar'=>'','fechaCreacion'=>'','fechaUltimoCambio'=>'','fechaExpira'=>'','ns1'=>'','ns2'=>'','nameservers'=>[]];
    $lineas      = explode("\n", $datos);
    $nameservers = [];

    foreach ($lineas as $linea) {
        $linea = trim($linea);
        if (empty($linea) || strpos($linea,'%')===0 || strpos($linea,'#')===0) continue;
        if (strpos($linea, ':') === false) continue;

        list($clave, $valor) = explode(':', $linea, 2);
        $clave = trim(strtolower($clave));
        $valor = trim($valor);

        switch ($clave) {
            case 'created on': case 'created': case 'creation date':
                if (empty($info['fechaCreacion'])) $info['fechaCreacion'] = formatearFechaMX($valor);
                break;
            case 'last updated on': case 'last updated': case 'changed': case 'updated date':
                if (empty($info['fechaUltimoCambio'])) $info['fechaUltimoCambio'] = formatearFechaMX($valor);
                break;
            case 'expiration date': case 'expires on': case 'expiry date': case 'registry expiry date':
                if (empty($info['fechaExpira'])) $info['fechaExpira'] = formatearFechaMX($valor);
                break;
            case 'registrar': case 'sponsoring registrar': case 'registrant':
                if (empty($info['registrar']) && !empty($valor)) $info['registrar'] = $valor;
                break;
            case 'name server': case 'nserver': case 'dns': case 'nameserver':
                if (!empty($valor)) {
                    $ns = strtolower(explode(' ', $valor)[0]);
                    if (!in_array($ns, $nameservers) && !empty($ns)) $nameservers[] = $ns;
                }
                break;
            case 'url': case 'registrar url':
                if (empty($info['registrar']) && !empty($valor)) {
                    $parsed = parse_url($valor);
                    if (isset($parsed['host'])) $info['registrar'] = $parsed['host'];
                }
                break;
        }
    }

    $info['nameservers'] = $nameservers;
    if (count($nameservers) > 0) $info['ns1'] = $nameservers[0];
    if (count($nameservers) > 1) $info['ns2'] = $nameservers[1];
    return $info;
}

function formatearFechaMX($fecha) {
    $fecha = trim($fecha);
    $fecha = preg_replace('/\s+/', ' ', $fecha);
    $fecha = str_replace(['(', ')'], '', $fecha);

    $formatosMX = [
        'Y-m-d', 'd-m-Y', 'd/m/Y', 'Y/m/d', 'd-M-Y',
        'Y-m-d H:i:s', 'd-m-Y H:i:s', 'Y-m-d\TH:i:s',
        'Y-m-d\TH:i:s\Z', 'D, d M Y', 'd M Y', 'M d, Y',
    ];

    foreach ($formatosMX as $formato) {
        $fechaObj = DateTime::createFromFormat($formato, $fecha);
        if ($fechaObj !== false) return $fechaObj->format('Y-m-d');
    }

    $timestamp = strtotime($fecha);
    if ($timestamp !== false) return date('Y-m-d', $timestamp);
    return '';
}

// ============================================================
// COLORES DE FILAS
// ============================================================

function get_dias_expiracion($expiration) {
    if (empty($expiration) || $expiration === '0000-00-00') return ['dias' => null, 'color' => ''];
    $exp  = new DateTime($expiration);
    $hoy  = new DateTime(date('Y-m-d'));
    $diff = $hoy->diff($exp);
    $dias = $diff->days;
    if ($exp < $hoy) $dias = -$dias;

    if ($dias < 0)        return ['dias' => $dias, 'color' => 'expired'];
    if ($dias < 14)       return ['dias' => $dias, 'color' => 'danger'];
    if ($dias < 60)       return ['dias' => $dias, 'color' => 'warning'];
    if ($dias > 370)      return ['dias' => $dias, 'color' => 'success'];
    return ['dias' => $dias, 'color' => 'normal'];
}

// ============================================================
// CONTROL DE ACCIONES
// ============================================================

$accion      = $_GET['accion'] ?? 'listado';
$mensaje     = '';
$tipo_mensaje= '';
$resultado_whois = '';

// POST: Actualizar WHOIS
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['actualizar_dominio'])) {
    $dom = trim($_POST['actualizar_dominio']);
    // Detectar .com.mx antes que .mx
    if (substr($dom, -7) === '.com.mx' || substr($dom, -3) === '.mx') {
        $resultado_whois = obtenerInfoDominioMX($dom);
    } else {
        $resultado_whois = obtenerInfoDominio($dom);
    }
    $mensaje      = 'WHOIS actualizado: ' . htmlspecialchars($dom);
    $tipo_mensaje = (strpos($resultado_whois, 'Error') !== false) ? 'danger' : 'success';
    $accion       = 'listado';
}

// Agregar dominio
if ($accion === 'agregar' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $dominio    = strtolower(trim($_POST['dominio'] ?? ''));
    $type       = $_POST['type']       ?? 'PROPIO';
    $iscustomer = $_POST['iscustomer'] ?? 'NO';
    $NOTA       = $_POST['NOTA']       ?? '';

    if (empty($dominio)) {
        $mensaje = 'El dominio es obligatorio';
        $tipo_mensaje = 'danger';
    } else {
        $stmt = mysqli_prepare($link,
            "INSERT INTO dominios2020 (dominio, servidores, type, iscustomer, NOTA, showit, last_updated)
             VALUES (?, '', ?, ?, ?, 'YES', NOW())");
        mysqli_stmt_bind_param($stmt, 'ssss', $dominio, $type, $iscustomer, $NOTA);
        if (mysqli_stmt_execute($stmt)) {
            $mensaje      = 'Dominio ' . htmlspecialchars($dominio) . ' agregado. Usa WHOIS para completar datos.';
            $tipo_mensaje = 'success';
        } else {
            $mensaje      = 'Error al agregar: ' . mysqli_error($link);
            $tipo_mensaje = 'danger';
        }
    }
    $accion = 'listado';
}

// Editar dominio
if ($accion === 'editar' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $dominio_original = $_POST['dominio_original'] ?? '';
    $type       = $_POST['type']       ?? 'PROPIO';
    $iscustomer = $_POST['iscustomer'] ?? 'NO';
    $NOTA       = $_POST['NOTA']       ?? '';
    $showit     = $_POST['showit']     ?? 'YES';

    $stmt = mysqli_prepare($link,
        "UPDATE dominios2020 SET type=?, iscustomer=?, NOTA=?, showit=? WHERE dominio=?");
    mysqli_stmt_bind_param($stmt, 'sssss', $type, $iscustomer, $NOTA, $showit, $dominio_original);
    if (mysqli_stmt_execute($stmt)) {
        $mensaje = 'Dominio actualizado';
        $tipo_mensaje = 'success';
    } else {
        $mensaje = 'Error: ' . mysqli_error($link);
        $tipo_mensaje = 'danger';
    }
    $accion = 'listado';
}

// Eliminar dominio
if ($accion === 'eliminar' && isset($_GET['dominio'])) {
    $dom  = $_GET['dominio'];
    $stmt = mysqli_prepare($link, "DELETE FROM dominios2020 WHERE dominio=?");
    mysqli_stmt_bind_param($stmt, 's', $dom);
    if (mysqli_stmt_execute($stmt)) {
        $mensaje = 'Dominio eliminado: ' . htmlspecialchars($dom);
        $tipo_mensaje = 'success';
    } else {
        $mensaje = 'Error: ' . mysqli_error($link);
        $tipo_mensaje = 'danger';
    }
    $accion = 'listado';
}

// ============================================================
// FILTROS Y CONSULTA PRINCIPAL
// ============================================================

$f_ext        = $_GET['f_ext']        ?? '';
$f_type       = $_GET['f_type']       ?? '';
$f_iscustomer = $_GET['f_iscustomer'] ?? '';
$f_registrar  = $_GET['f_registrar']  ?? '';
$solo_actualizados = isset($_GET['solo_actualizados']) && $_GET['solo_actualizados'] == '1';

$where  = " WHERE showit = 'YES'";
$params = [];
$types  = '';

if ($solo_actualizados) {
    $where .= " AND last_updated IS NOT NULL AND last_updated >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)";
}
if ($f_ext) {
    if ($f_ext === 'com.mx') {
        $where .= " AND dominio LIKE ?";
        $params[] = '%.com.mx'; $types .= 's';
    } elseif ($f_ext === 'mx') {
        $where .= " AND dominio LIKE ? AND dominio NOT LIKE ?";
        $params[] = '%.mx'; $params[] = '%.com.mx'; $types .= 'ss';
    } else {
        $where .= " AND dominio LIKE ?";
        $params[] = '%.' . $f_ext; $types .= 's';
    }
}
if ($f_type)       { $where .= " AND type = ?";         $params[] = $f_type;       $types .= 's'; }
if ($f_iscustomer) { $where .= " AND iscustomer = ?";   $params[] = $f_iscustomer; $types .= 's'; }
if ($f_registrar)  { $where .= " AND registrar LIKE ?"; $params[] = "%$f_registrar%"; $types .= 's'; }

$stmt = mysqli_prepare($link, "SELECT * FROM dominios2020 $where ORDER BY expiration ASC, dominio ASC");
if (!empty($types)) mysqli_stmt_bind_param($stmt, $types, ...$params);
mysqli_stmt_execute($stmt);
$result    = mysqli_stmt_get_result($stmt);
$dominios  = [];
while ($row = mysqli_fetch_assoc($result)) {
    $row['dias_info'] = get_dias_expiracion($row['expiration']);
    $dominios[] = $row;
}

// Listas para filtros
$registrars = [];
$res_r = mysqli_query($link, "SELECT DISTINCT registrar FROM dominios2020 WHERE registrar IS NOT NULL AND registrar != '' ORDER BY registrar");
while ($r = mysqli_fetch_assoc($res_r)) $registrars[] = $r['registrar'];

// Dominio para editar
$dominio_editar = null;
if ($accion === 'editar' && isset($_GET['dominio'])) {
    $stmt_e = mysqli_prepare($link, "SELECT * FROM dominios2020 WHERE dominio = ?");
    mysqli_stmt_bind_param($stmt_e, 's', $_GET['dominio']);
    mysqli_stmt_execute($stmt_e);
    $dominio_editar = mysqli_stmt_get_result($stmt_e)->fetch_assoc();
}

$extensiones_validas = ['.com','.net','.org','.info','.monster','.xyz','.vip','.mom','.mx','.com.mx'];
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
            --metro-blue:   #3498db;
            --metro-green:  #27ae60;
            --metro-red:    #e74c3c;
            --metro-orange: #e67e22;
            --nav-bg:       linear-gradient(135deg, #2c3e50, #34495e);
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, sans-serif;
            background: linear-gradient(135deg, #1a2a6c 0%, #2c3e50 50%, #4a69bd 100%);
            min-height: 100vh;
            padding-top: 75px;
            padding-bottom: 70px;
        }

        /* ---- NAVBAR ---- */
        .navbar {
            background: var(--nav-bg) !important;
            box-shadow: 0 2px 10px rgba(0,0,0,.35);
        }
        .navbar-brand { font-weight: 700; }

        /* ---- CARDS ---- */
        .card-metro {
            background: #fff;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,.25);
            overflow: visible; /* importante: visible para que los dropdowns no queden ocultos */
            border: none;
            margin-bottom: 1.5rem;
        }
        .card-header-metro {
            background: var(--nav-bg);
            color: #fff;
            padding: 14px 20px;
            border-radius: 15px 15px 0 0;
        }

        /* ---- BOTONES ---- */
        .btn-metro {
            background: var(--nav-bg);
            color: #fff;
            border: none;
            border-radius: 8px;
            padding: 8px 18px;
            transition: all .25s;
        }
        .btn-metro:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,.25); color: #fff; }

        /* ---- FILTROS ---- */
        .filter-section {
            background: #fff;
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 1rem;
            box-shadow: 0 4px 15px rgba(0,0,0,.1);
        }

        /* ---- TABLA ---- */
        .table-wrap {
            border-radius: 0 0 15px 15px;
            overflow: visible; /* visible para dropdowns */
        }
        .table thead th {
            background: var(--nav-bg);
            color: #fff;
            border: none;
            font-size: .82rem;
            white-space: nowrap;
        }
        .table td { vertical-align: middle; font-size: .85rem; }

        /* ---- COLORES DE FILAS ---- */
        tr.fila-danger  td { background-color: #fde8e8 !important; }
        tr.fila-warning td { background-color: #fef9e7 !important; }
        tr.fila-success td { background-color: #eafaf1 !important; }
        tr.fila-expired td { background-color: #f2f2f2 !important; color: #999; text-decoration: line-through; }

        /* ---- FOOTER FIJO ---- */
        footer.footer-fixed {
            background: var(--nav-bg);
            color: rgba(255,255,255,.85);
            position: fixed;
            bottom: 0; width: 100%; z-index: 1030;
            padding: 7px 0; font-size: .78rem; text-align: center;
        }

        /* ---- ACCIONES — garantizar visibilidad de botones ---- */
        .acciones-col {
            white-space: nowrap;
            min-width: 110px;
        }
        .acciones-col .btn { margin-bottom: 2px; }

        /* ---- LEYENDA ---- */
        .leyenda span {
            display: inline-block; width: 14px; height: 14px;
            border-radius: 3px; margin-right: 4px; vertical-align: middle;
        }
    </style>
</head>
<body>

<!-- NAVBAR -->
<nav class="navbar navbar-expand-lg navbar-dark fixed-top">
    <div class="container">
        <a class="navbar-brand" href="?">
            <i class="fas fa-globe mr-2"></i>Dominios
        </a>
        <span class="navbar-text text-white-50 small mr-3">
            <i class="fas fa-robot mr-1"></i>Humano + MiniMax
        </span>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navMain">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navMain">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item">
                    <a class="nav-link" href="?"><i class="fas fa-list mr-1"></i>Ver Todos</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?accion=agregar"><i class="fas fa-plus mr-1"></i>Agregar</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="https://www.google.com" target="_blank">
                        <i class="fab fa-google mr-1"></i>Google
                    </a>
                </li>
            </ul>
        </div>
    </div>
</nav>

<div class="container">

    <?php if ($mensaje): ?>
    <div class="alert alert-<?php echo $tipo_mensaje; ?> alert-dismissible fade show mt-3">
        <i class="fas <?php echo $tipo_mensaje==='success'?'fa-check-circle':'fa-exclamation-circle'; ?> mr-2"></i>
        <?php echo $mensaje; ?>
        <button type="button" class="close" data-dismiss="alert">&times;</button>
    </div>
    <?php endif; ?>

    <?php
    // ==============================================================
    // LISTADO
    // ==============================================================
    if ($accion === 'listado'):
    ?>

    <!-- Filtros -->
    <div class="filter-section mt-3">
        <form method="GET">
            <input type="hidden" name="accion" value="listado">
            <div class="row">
                <div class="col-6 col-md-2 mb-2">
                    <select name="f_ext" class="form-control form-control-sm">
                        <option value="">Todas las ext.</option>
                        <?php foreach (['.com','.net','.org','.info','.monster','.xyz','.vip','.mom','.mx','.com.mx'] as $ext): ?>
                        <option value="<?php echo ltrim($ext,'.'); ?>" <?php echo $f_ext===ltrim($ext,'.')?'selected':''; ?>><?php echo $ext; ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-6 col-md-2 mb-2">
                    <select name="f_iscustomer" class="form-control form-control-sm">
                        <option value="">Todos</option>
                        <option value="YES" <?php echo $f_iscustomer==='YES'?'selected':''; ?>>Clientes</option>
                        <option value="NO"  <?php echo $f_iscustomer==='NO' ?'selected':''; ?>>No clientes</option>
                    </select>
                </div>
                <div class="col-6 col-md-3 mb-2">
                    <select name="f_registrar" class="form-control form-control-sm">
                        <option value="">Todos los registrars</option>
                        <?php foreach ($registrars as $reg): ?>
                        <option value="<?php echo htmlspecialchars($reg); ?>" <?php echo $f_registrar===$reg?'selected':''; ?>><?php echo htmlspecialchars($reg); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-6 col-md-2 mb-2">
                    <select name="solo_actualizados" class="form-control form-control-sm">
                        <option value="0" <?php echo !$solo_actualizados?'selected':''; ?>>Todos</option>
                        <option value="1" <?php echo $solo_actualizados?'selected':''; ?>>Últ. 7 días</option>
                    </select>
                </div>
                <div class="col-12 col-md-3 mb-2">
                    <button type="submit" class="btn btn-metro btn-sm mr-1">
                        <i class="fas fa-filter mr-1"></i>Filtrar
                    </button>
                    <a href="?" class="btn btn-outline-light btn-sm mr-1">
                        <i class="fas fa-times mr-1"></i>Limpiar
                    </a>
                    <a href="?accion=agregar" class="btn btn-success btn-sm">
                        <i class="fas fa-plus mr-1"></i>Nuevo
                    </a>
                </div>
            </div>
        </form>

        <!-- Leyenda -->
        <div class="leyenda mt-1 small text-muted">
            <span style="background:#e74c3c;"></span>&lt;14 días &nbsp;
            <span style="background:#f1c40f;"></span>&lt;60 días &nbsp;
            <span style="background:#27ae60;"></span>&gt;370 días &nbsp;
            <span style="background:#bbb;"></span>Vencido
        </div>
    </div>

    <!-- Tabla -->
    <div class="card-metro">
        <div class="card-header-metro d-flex justify-content-between align-items-center">
            <h5 class="mb-0"><i class="fas fa-globe mr-2"></i>Control de Dominios</h5>
            <small><?php echo count($dominios); ?> registro(s)</small>
        </div>
        <div class="table-wrap">
            <div class="table">
                <table class="table table-hover mb-0">
                    </table>
                    <table class="table table-sm" style="width: 100%; table-layout: auto; min-width: 800px;">    
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Dominio</th>
                            <th>Name Servers</th>
                            <th>Registrado</th>
                            <th>Expira</th>
                            <th>Días</th>
                            <th>Registrar</th>
                            <th>Tipo</th>
                            <th>Cliente</th>
                            <th>Actualizado</th>
                            <th>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php $csh = 0; foreach ($dominios as $d):
                        $csh++;
                        $color = $d['dias_info']['color'];
                        $dias  = $d['dias_info']['dias'];
                        $fila_class = in_array($color,['danger','warning','success','expired']) ? 'fila-'.$color : '';
                        $txt_class  = in_array($color,['danger','success','expired']) ? 'text-dark' : '';
                    ?>
                    <tr class="<?php echo $fila_class; ?>">
                        <td><?php echo $csh; ?></td>
                        <td>
                            <strong><?php echo htmlspecialchars($d['dominio']); ?></strong>
                            <?php if (!empty($d['NOTA'])): ?>
                            <br><small class="text-muted"><?php echo htmlspecialchars(substr($d['NOTA'],0,50)); ?><?php echo strlen($d['NOTA'])>50?'...':''; ?></small>
                            <?php endif; ?>
                        </td>
                        <td><small><?php echo htmlspecialchars($d['servidores']); ?></small></td>
                        <td><small><?php echo $d['registered'] ? date('d/m/Y', strtotime($d['registered'])) : '—'; ?></small></td>
                        <td><small><?php echo $d['expiration'] ? date('d/m/Y', strtotime($d['expiration'])) : '—'; ?></small></td>
                        <td>
                            <?php if ($dias !== null):
                                $bc = $color==='danger'?'badge-danger':($color==='warning'?'badge-warning':($color==='success'?'badge-success':($color==='expired'?'badge-dark':'badge-secondary')));
                            ?>
                            <span class="badge <?php echo $bc; ?>">
                                <?php echo $dias < 0 ? 'Vencido' : $dias.' días'; ?>
                            </span>
                            <?php else: ?>—<?php endif; ?>
                        </td>
                        <td><small><?php echo htmlspecialchars($d['registrar'] ?? ''); ?></small></td>
                        <td>
                            <span class="badge <?php echo $d['type']==='CLIENTE'?'badge-primary':($d['type']==='PROPIO'?'badge-info':'badge-secondary'); ?>">
                                <?php echo htmlspecialchars($d['type']); ?>
                            </span>
                        </td>
                        <td>
                            <?php if ($d['iscustomer']==='YES'): ?>
                            <i class="fas fa-check-circle text-success"></i>
                            <?php else: ?>
                            <i class="fas fa-times-circle text-muted"></i>
                            <?php endif; ?>
                        </td>
                        <td><small><?php echo $d['last_updated'] ? date('d/m/Y', strtotime($d['last_updated'])) : '—'; ?></small></td>
                        <td class="acciones-col">
                            <!-- WHOIS via POST -->
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="actualizar_dominio" value="<?php echo htmlspecialchars($d['dominio']); ?>">
                                <button type="submit" class="btn btn-sm btn-info" title="Actualizar WHOIS">
                                    <i class="fas fa-sync-alt"></i>
                                </button>
                            </form>
                            <!-- Ir al sitio -->
                            <a href="https://<?php echo htmlspecialchars($d['dominio']); ?>" target="_blank" class="btn btn-sm btn-success" title="Ir al sitio">
                                <i class="fas fa-home"></i>
                            </a>
                            <!-- Editar -->
                            <a href="?accion=editar&dominio=<?php echo urlencode($d['dominio']); ?>" class="btn btn-sm btn-warning" title="Editar">
                                <i class="fas fa-edit"></i>
                            </a>
                            <!-- Eliminar -->
                            <a href="?accion=eliminar&dominio=<?php echo urlencode($d['dominio']); ?>"
                               class="btn btn-sm btn-danger" title="Eliminar"
                               onclick="return confirm('¿Eliminar <?php echo htmlspecialchars($d['dominio']); ?>?')">
                                <i class="fas fa-trash"></i>
                            </a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($dominios)): ?>
                    <tr>
                        <td colspan="11" class="text-center text-muted py-5">
                            <i class="fas fa-globe fa-2x d-block mb-2"></i>
                            No hay dominios registrados
                            <br><a href="?accion=agregar" class="btn btn-metro mt-2"><i class="fas fa-plus mr-1"></i>Agregar primero</a>
                        </td>
                    </tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <?php
    // ==============================================================
    // AGREGAR DOMINIO
    // ==============================================================
    elseif ($accion === 'agregar'):
    ?>
    <div class="row justify-content-center mt-4">
        <div class="col-md-6">
            <div class="card-metro">
                <div class="card-header-metro">
                    <h5 class="mb-0"><i class="fas fa-plus mr-2"></i>Agregar Dominio</h5>
                </div>
                <div class="card-body p-4">
                    <form method="POST" action="?accion=agregar">
                        <div class="form-group">
                            <label><i class="fas fa-globe mr-1"></i> Dominio</label>
                            <input type="text" name="dominio" class="form-control" placeholder="ejemplo.com" required>
                            <small class="text-muted">Extensiones: <?php echo implode(', ', $extensiones_validas); ?></small>
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-tag mr-1"></i> Tipo</label>
                            <select name="type" class="form-control">
                                <option value="PROPIO">Propio</option>
                                <option value="CLIENTE">Cliente</option>
                                <option value="PROYECTO">Proyecto</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-user mr-1"></i> ¿Es cliente?</label>
                            <select name="iscustomer" class="form-control">
                                <option value="NO">No</option>
                                <option value="YES">Sí</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-comment mr-1"></i> Nota</label>
                            <textarea name="NOTA" class="form-control" rows="2"></textarea>
                        </div>
                        <button type="submit" class="btn btn-metro btn-block">
                            <i class="fas fa-plus mr-2"></i>Agregar Dominio
                        </button>
                        <a href="?" class="btn btn-outline-secondary btn-block mt-2">Cancelar</a>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <?php
    // ==============================================================
    // EDITAR DOMINIO
    // ==============================================================
    elseif ($accion === 'editar' && $dominio_editar):
    ?>
    <div class="row justify-content-center mt-4">
        <div class="col-md-6">
            <div class="card-metro">
                <div class="card-header-metro">
                    <h5 class="mb-0"><i class="fas fa-edit mr-2"></i>Editar: <?php echo htmlspecialchars($dominio_editar['dominio']); ?></h5>
                </div>
                <div class="card-body p-4">
                    <form method="POST" action="?accion=editar">
                        <input type="hidden" name="dominio_original" value="<?php echo htmlspecialchars($dominio_editar['dominio']); ?>">

                        <div class="form-group">
                            <label><i class="fas fa-globe mr-1"></i> Dominio</label>
                            <input type="text" class="form-control" value="<?php echo htmlspecialchars($dominio_editar['dominio']); ?>" readonly>
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-server mr-1"></i> Name Servers <small class="text-muted">(usa WHOIS para actualizar)</small></label>
                            <input type="text" class="form-control" value="<?php echo htmlspecialchars($dominio_editar['servidores']); ?>" readonly>
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-tag mr-1"></i> Tipo</label>
                            <select name="type" class="form-control">
                                <?php foreach (['PROPIO','CLIENTE','PROYECTO'] as $t): ?>
                                <option value="<?php echo $t; ?>" <?php echo $dominio_editar['type']===$t?'selected':''; ?>><?php echo $t; ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-user mr-1"></i> ¿Es cliente?</label>
                            <select name="iscustomer" class="form-control">
                                <option value="NO"  <?php echo $dominio_editar['iscustomer']==='NO' ?'selected':''; ?>>No</option>
                                <option value="YES" <?php echo $dominio_editar['iscustomer']==='YES'?'selected':''; ?>>Sí</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-eye mr-1"></i> Visible</label>
                            <select name="showit" class="form-control">
                                <option value="YES" <?php echo $dominio_editar['showit']==='YES'?'selected':''; ?>>Sí</option>
                                <option value="NO"  <?php echo $dominio_editar['showit']==='NO' ?'selected':''; ?>>No</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-comment mr-1"></i> Nota</label>
                            <textarea name="NOTA" class="form-control" rows="2"><?php echo htmlspecialchars($dominio_editar['NOTA'] ?? ''); ?></textarea>
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

</div><!-- /container -->

<!-- FOOTER FIJO -->
<footer class="footer-fixed">
    <i class="fas fa-globe mr-1"></i>Dominios &nbsp;|&nbsp;
    <i class="fas fa-code mr-1"></i>PHP <?php echo phpversion(); ?> &nbsp;|&nbsp;
    <i class="fas fa-robot mr-1"></i>Humano + MiniMax-M2.5 &nbsp;|&nbsp;
    <i class="fas fa-calendar mr-1"></i><?php echo date('Y-m-d H:i'); ?>
</footer>

<script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php mysqli_close($link); ?>