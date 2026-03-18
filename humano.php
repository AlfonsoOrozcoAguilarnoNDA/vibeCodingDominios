<?php
 humano.php - Control de Dominios y Expiraciones
    
    Copyright (C) 2019 Alfonso Orozco Aguilar (Alfonso Orozco Aguilar)
Licencia MIT, si teexplotaes asunto tuyo

Se hizo para controlar una lista de dominios existentes de otro proyecto, por eso no lleva altas bajas ni cambios.
*/
$db_user = 'yours';
$db_pass = 'yours';
$db_name = 'yours';

// Configuración de la base de datos
$host = 'localhost';
$db_host = 'localhost';

$link = mysqli_connect($db_host, $db_user, $db_pass, $db_name);

// Verificar conexión
if (!$link) {
    die("Error de conexión: " . mysqli_connect_error());
}

// Configurar charset UTF-8
mysqli_set_charset($link, "utf8");

// Ejemplo de uso
/*
echo obtenerInfoDominio('google.com') . "\n";
echo obtenerInfoDominio('wikipedia.org') . "\n";
echo obtenerInfoDominio('example.net') . "\n";
echo obtenerInfoDominio('test.info') . "\n";
echo obtenerInfoDominio('example.com.mx') . "\n";
*/
/*
echo "<li>".obtenerInfoDominio('alfonsoorozco.com') . "\n";

//echo "<li>".obtenerInfoDominio('google.com') . "\n";
echo "<li>".obtenerInfoDominio('nahual.org') . "\n";
echo "<li>".obtenerInfoDominio('nahual.net') . "\n";
echo "<li>".obtenerInfoDominio('chamanismo.info') . "\n";
echo "<li>".obtenerInfoDominio('coparoms.com.mx') . "\n";
echo "<li>".obtenerInfoDominio('example.com.mx') . "\n";

*/

$solo_actualizados = isset($_GET['solo_actualizados']) && $_GET['solo_actualizados'] == '1';
$filtro_extension = isset($_GET['filtro_extension']) ? $_GET['filtro_extension'] : 'TODOS';
$filtro_clientes = isset($_GET['filtro_clientes']) ? $_GET['filtro_clientes'] : 'TODOS';

// Generar y mostrar la interfaz
$interfaz_html = generar_interfaz_dominios($link, $solo_actualizados, $filtro_extension,$filtro_clientes);
echo inicio();

if (isset($_POST['actualizar_dominio'])) {
   /*echo "<pre>";
   print_r($_POST);
   die("</pre>");
   */
   $dom=$_POST['actualizar_dominio'];
/*   echo "<pre>";
   print_r(obtenerInfoDominioMX($dom));
   die("</pre>");
   */
   if (right($dom,3)==='.mx') echo "<li>".obtenerInfoDominioMX($dom) . "\n";
   if (right($dom,3)<>'.mx') echo "<li>".obtenerInfoDominio($dom) . "\n";
   
    // Aquí llamarías a tu función de actualización existente
    // actualizar_dominios();
}
echo esfinal();


echo $interfaz_html;


// Manejar el POST de actualización

//------------------------------------------
function obtenerInfoDominio($dominio) {
    // Limpiar el dominio de espacios y convertir a minúsculas
    $dominio = strtolower(trim($dominio));
    
    // Validar formato de dominio
    if (!filter_var($dominio, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return "||Error: Dominio inválido||||||||";
    }
    
    // Obtener la extensión del dominio
    $extension = substr($dominio, strrpos($dominio, '.'));
    
    // Servidores WHOIS según la extensión
    $servidoresWhois = [
        '.com' => 'whois.verisign-grs.com',
        '.net' => 'whois.verisign-grs.com',
        '.org' => 'whois.pir.org',
        '.info' => 'whois.afilias.net',
        '.vip' => 'whois.nic.vip',
        '.mx' => 'whois.mx',
        '.com.mx' => 'whois.mx'
    ];
    
    // Verificar si la extensión es soportada
    if (!isset($servidoresWhois[$extension])) {
        return "||Error: Extensión no soportada||||||||";
    }
    
    $servidorWhois = $servidoresWhois[$extension];
    
    // Realizar consulta WHOIS
    $datosWhois = consultarWhois($dominio, $servidorWhois);
    
    if (!$datosWhois) {
        return "||Error: No se pudo obtener información WHOIS||||||||";
    }
    
    // Parsear los datos según la extensión
    $info = parsearDatosWhois($datosWhois, $extension);
    $info['registrar']=trim($info['registrar']);
    
    $servidores= $info['ns1'] ?? '';
      $servidores.= ",". $info['ns2'] ?? '';
      $sql="update dominios2020 set servidores='$servidores',registered='".$info['fechaCreacion']."',
      expiration='".$info['fechaExpira']."',
      registrar='".$info['registrar']."',
      last_updated=now()
            
       where dominio='$dominio'";
    //   die($sql);
    
    // Formatear la respuesta
    //if ($info['registrar']=="Porkbun LLC"){
      
       list($dummy)=avalues319($sql);
    //}
    return sprintf(
        "||%s|%s|%s|%s|%s|%s|%s||",
        $dominio,
        $info['registrar'] ?? '',
        $info['fechaCreacion'] ?? '',
        $info['fechaUltimoCambio'] ?? '',
        $info['fechaExpira'] ?? '',
        $info['ns1'] ?? '',
        $info['ns2'] ?? ''
    );
}

function consultarWhois($dominio, $servidor, $puerto = 43) {
    // Crear conexión socket
    $socket = fsockopen($servidor, $puerto, $errno, $errstr, 10);
    
    if (!$socket) {
        return false;
    }
    
    // Enviar consulta
    fwrite($socket, $dominio . "\r\n");
    
    // Leer respuesta
    $respuesta = '';
    while (!feof($socket)) {
        $respuesta .= fgets($socket, 1024);
    }
    
    fclose($socket);
    
    return $respuesta;
}

function parsearDatosWhois($datos, $extension) {
    $info = [
        'registrar' => '',
        'fechaCreacion' => '',
        'fechaUltimoCambio' => '',
        'fechaExpira' => '',
        'ns1' => '',
        'ns2' => ''
    ];
    
    $lineas = explode("\n", $datos);
    $nameservers = [];
    
    foreach ($lineas as $linea) {
        $linea = trim($linea);
        
        if ($extension === '.com.mx') {
            // Patrones específicos para .com.mx (NIC México)
            if (preg_match('/^Created On:\s*(.+)$/i', $linea, $matches)) {
                $info['fechaCreacion'] = formatearFecha($matches[1]);
            }
            elseif (preg_match('/^Last Updated On:\s*(.+)$/i', $linea, $matches)) {
                $info['fechaUltimoCambio'] = formatearFecha($matches[1]);
            }
            elseif (preg_match('/^Expiration Date:\s*(.+)$/i', $linea, $matches)) {
                $info['fechaExpira'] = formatearFecha($matches[1]);
            }
            elseif (preg_match('/^Changed:\s*(.+)$/i', $linea, $matches)) {
                if (empty($info['fechaUltimoCambio'])) {
                    $info['fechaUltimoCambio'] = formatearFecha($matches[1]);
                }
            }
            elseif (preg_match('/^Registrar:\s*(.+)$/i', $linea, $matches)) {
                $info['registrar'] = trim($matches[1]);
            }
            elseif (preg_match('/^URL:\s*(.+)$/i', $linea, $matches)) {
                if (empty($info['registrar'])) {
                    $info['registrar'] = trim($matches[1]);
                }
            }
            elseif (preg_match('/^DNS:\s*(.+)$/i', $linea, $matches)) {
                $nameservers[] = strtolower(trim($matches[1]));
            }
        } else {
            // Patrones para .com, .net, .org, .info con múltiples variaciones
            if (preg_match('/^Registrar:\s*(.+)$/i', $linea, $matches)) {
                $info['registrar'] = trim($matches[1]);
            }
            elseif (preg_match('/^Sponsoring Registrar:\s*(.+)$/i', $linea, $matches)) {
                if (empty($info['registrar'])) {
                    $info['registrar'] = trim($matches[1]);
                }
            }
            elseif (preg_match('/^Creation Date:\s*(.+)$/i', $linea, $matches)) {
                $info['fechaCreacion'] = formatearFecha($matches[1]);
            }
            elseif (preg_match('/^Created On:\s*(.+)$/i', $linea, $matches)) {
                if (empty($info['fechaCreacion'])) {
                    $info['fechaCreacion'] = formatearFecha($matches[1]);
                }
            }
            elseif (preg_match('/^Updated Date:\s*(.+)$/i', $linea, $matches)) {
                $info['fechaUltimoCambio'] = formatearFecha($matches[1]);
            }
            elseif (preg_match('/^Last Updated On:\s*(.+)$/i', $linea, $matches)) {
                if (empty($info['fechaUltimoCambio'])) {
                    $info['fechaUltimoCambio'] = formatearFecha($matches[1]);
                }
            }
            // Múltiples patrones para fecha de expiración
            elseif (preg_match('/^Registry Expiry Date:\s*(.+)$/i', $linea, $matches)) {
                $info['fechaExpira'] = formatearFecha($matches[1]);
            }
            elseif (preg_match('/^Registrar Registration Expiration Date:\s*(.+)$/i', $linea, $matches)) {
                if (empty($info['fechaExpira'])) {
                    $info['fechaExpira'] = formatearFecha($matches[1]);
                }
            }
            elseif (preg_match('/^Expir(?:y|ation) Date:\s*(.+)$/i', $linea, $matches)) {
                if (empty($info['fechaExpira'])) {
                    $info['fechaExpira'] = formatearFecha($matches[1]);
                }
            }
            elseif (preg_match('/^Expires.*:\s*(.+)$/i', $linea, $matches)) {
                if (empty($info['fechaExpira'])) {
                    $info['fechaExpira'] = formatearFecha($matches[1]);
                }
            }
            // Múltiples patrones para nameservers
            elseif (preg_match('/^Name Server:\s*(.+)$/i', $linea, $matches)) {
                $nameservers[] = strtolower(trim($matches[1]));
            }
            elseif (preg_match('/^nserver:\s*(.+)$/i', $linea, $matches)) {
                $nameservers[] = strtolower(trim($matches[1]));
            }
        }
    }
    
    // Asignar los primeros dos nameservers
    if (count($nameservers) > 0) {
        $info['ns1'] = $nameservers[0];
    }
    if (count($nameservers) > 1) {
        $info['ns2'] = $nameservers[1];
    }
    
    return $info;
}

function formatearFecha($fecha) {
    $fecha = trim($fecha);
    
    // Limpiar caracteres extra y espacios múltiples
    $fecha = preg_replace('/\s+/', ' ', $fecha);
    
    // Intentar parsear diferentes formatos de fecha
    $formatos = [
        'Y-m-d\TH:i:s\Z',           // 2024-01-15T12:30:45Z
        'Y-m-d\TH:i:s.u\Z',        // 2024-01-15T12:30:45.123Z
        'Y-m-d H:i:s \U\T\C',      // 2024-01-15 12:30:45 UTC
        'Y-m-d H:i:s',             // 2024-01-15 12:30:45
        'Y-m-d',                   // 2024-01-15
        'd-M-Y',                   // 15-Jan-2024
        'M d Y',                   // Jan 15 2024
        'd/m/Y',                   // 15/01/2024
        'm/d/Y',                   // 01/15/2024
        'Y/m/d',                   // 2024/01/15
        'D M d H:i:s Y',           // Mon Jan 15 12:30:45 2024
        'D, d M Y H:i:s \U\T\C',   // Mon, 15 Jan 2024 12:30:45 UTC
        'Y-m-d\TH:i:s',            // 2024-01-15T12:30:45
        'd-m-Y',                   // 15-01-2024
    ];
    
    foreach ($formatos as $formato) {
        $fechaObj = DateTime::createFromFormat($formato, $fecha);
        if ($fechaObj !== false) {
            return $fechaObj->format('Y-m-d');
        }
    }
    
    // Intentar con strtotime como último recurso
    $timestamp = strtotime($fecha);
    if ($timestamp !== false) {
        return date('Y-m-d', $timestamp);
    }
    
    // Si no se pudo parsear, devolver la fecha original limpia
    return $fecha;
}

function aValues319($Qx){
global $link;    
    $rsX = mysqli_query($link,$Qx) or mysqli_error($link);// sqlerror("error checking avalues<hr>$Qx"); //  or die("<hr>Avalues 319<hr>$Qx");
    $Qx2=strtolower($Qx);
    if (left($Qx2,6)<>'select') return "";    
    $aDataX = array();
    $rows=mysqli_num_rows($rsX);
    if ($rows==0) return array("",""); 
        
        $Campos = mysqli_num_fields($rsX);
        while ($regX = mysqli_fetch_array($rsX)) {
            for($iX=0; $iX<$Campos; $iX++){
               $finfo=mysqli_fetch_field_direct($rsX,$iX);
               $name=$finfo->name;
                $aDataX[] = $regX[ $name ];
            }
        }
      // echo ($Qx ."/". $aDataX[0]);
    return $aDataX;
}
function left($str, $length) {
     return substr($str, 0, $length);
}

function right($str, $length) {
     return substr($str, -$length);
}

/**
 * Genera la interfaz completa para mostrar dominios con filtros
 * @param mysqli $link - Conexión a la base de datos
 * @param bool $solo_actualizados - Filtrar solo los actualizados en últimos 7 días
 * @param string $filtro_extension - 'TODOS', 'SIN_MX', 'SIN_COM_MX'
 * @param string $filtro_clientes - 'TODOS', 'CLIENTES', 'NO CLIENTES'
 * @return string - HTML completo de la interfaz
 */
function generar_interfaz_dominios($link, $solo_actualizados = false, $filtro_extension = 'TODOS', $filtro_clientes = 'TODOS') {
    
    // Construir la consulta SQL
    $sql = "SELECT dominio, servidores, registered, expiration, registrar, 
                   showit, iscustomer, type, NOTA, last_updated 
            FROM dominios2020 
            WHERE showit = 'YES'";
   if ($filtro_clientes==="CLIENTES") $sql .= " and iscustomer ='YES'";         
   if ($filtro_clientes==="NO CLIENTES") $sql .= " and iscustomer <>'YES'";
    
    // Aplicar filtro de actualización (últimos 7 días)
    if ($solo_actualizados) {
        $sql .= " AND last_updated IS NOT NULL AND last_updated >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)";
    }
    
    // Aplicar filtro de extensiones
    switch ($filtro_extension) {
        case 'SIN_MX':
            $sql .= " AND dominio NOT LIKE '%.mx'";
            break;
        case 'SIN_COM_MX':
            $sql .= " AND dominio NOT LIKE '%.com.mx'";
            break;
        case 'TODOS':
        default:
            // No agregar filtro adicional
            break;
    }
    
    $sql .= " ORDER BY expiration , dominio ASC";
    
    // Ejecutar consulta
    $resultado = mysqli_query($link, $sql);
    //echo "<h3>$sql</h3>";
    if (!$resultado) {
        return '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> Error en la consulta: ' . mysqli_error($link) . '</div>';
    }
    
    // Contar total de registros
    $total_registros = mysqli_num_rows($resultado);
    
    // Generar HTML
    $html = '';
    
    // Header con título y estadísticas
    $html .= '
    <div class="container-fluid mt-3">
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">
                            <i class="fas fa-globe"></i> Control de Dominios
                            <span class="badge badge-light ml-2">' . $total_registros . ' dominios</span>
                        </h4>
                    </div>
                    <div class="card-body">
                        
                        <!-- Filtros -->
                        <form method="GET" class="mb-3">
                            <div class="row">
                                <div class="col-md-3">
                                    <div class="form-group">
                                        <label for="solo_actualizados">
                                            <i class="fas fa-calendar-check"></i> Filtro temporal
                                        </label>
                                        <select name="solo_actualizados" id="solo_actualizados" class="form-control">
                                            <option value="0"' . (!$solo_actualizados ? ' selected' : '') . '>Todos los dominios</option>
                                            <option value="1"' . ($solo_actualizados ? ' selected' : '') . '>Actualizados últimos 7 días</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="form-group">
                                        <label for="filtro_extension">
                                            <i class="fas fa-filter"></i> Filtro de extensiones
                                        </label>
                                        <select name="filtro_extension" id="filtro_extension" class="form-control">
                                            <option value="TODOS"' . ($filtro_extension == 'TODOS' ? ' selected' : '') . '>Mostrar todos</option>
                                            <option value="SIN_MX"' . ($filtro_extension == 'SIN_MX' ? ' selected' : '') . '>Ocultar .mx</option>
                                            <option value="SIN_COM_MX"' . ($filtro_extension == 'SIN_COM_MX' ? ' selected' : '') . '>Ocultar .com.mx</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="form-group">
                                        <label for="filtro_clientes">
                                            <i class="fas fa-handshake"></i> Filtro de Clientes
                                        </label>
                                        <select name="filtro_clientes" id="filtro_clientes" class="form-control">
                                            <option value="TODOS"' . ($filtro_clientes == 'TODOS' ? ' selected' : '') . '>Mostrar todos</option>
                                            <option value="CLIENTES"' . ($filtro_clientes == 'CLIENTES' ? ' selected' : '') . '>Clientes</option>
                                            <option value="NO CLIENTES"' . ($filtro_clientes == 'NO CLIENTES' ? ' selected' : '') . '>No Clientes</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="form-group">
                                        <label>&nbsp;</label><br>
                                        <button type="submit" class="btn btn-info">
                                            <i class="fas fa-search"></i> Filtrar
                                        </button>
                                        <a href="?" class="btn btn-secondary">
                                            <i class="fas fa-times"></i> Limpiar
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </form>';
    
    // Tabla de dominios
    if ($total_registros > 0) {
        $html .= '
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead class="thead-dark">
                                    <tr>
                                        <th>#</th>
                                        <th><i class="fas fa-globe"></i> Dominio</th>
                                        <th><i class="fas fa-server"></i> Servidores</th>
                                        <th><i class="fas fa-calendar-plus"></i> Registrado</th>
                                        <th><i class="fas fa-calendar-times"></i> Expira</th>
                                        <th><i class="fas fa-building"></i> Registrar</th>
                                        <th><i class="fas fa-tag"></i> Tipo</th>
                                        <th><i class="fas fa-user-check"></i> Cliente</th>
                                        <th><i class="fas fa-calendar-check"></i> Actualizado</th>
                                        <th><i class="fas fa-sticky-note"></i> Nota</th>
                                        <th><i class="fas fa-cogs"></i> Acciones</th>
                                    </tr>
                                </thead>
                                <tbody>';
        $csh=0;
        while ($fila = mysqli_fetch_assoc($resultado)) {
            
            // Calcular días hasta expiración
            $hoy = new DateTime();
            $expiracion = new DateTime($fila['expiration']);
            $dias_restantes = $hoy->diff($expiracion)->days;
            $expira_pronto = ($dias_restantes <= 30);
            
            // Determinar si fue actualizado recientemente
            $actualizado_reciente = false;
            if ($fila['last_updated']) {
                $ultima_actualizacion = new DateTime($fila['last_updated']);
                $dias_desde_actualizacion = $hoy->diff($ultima_actualizacion)->days;
                $actualizado_reciente = ($dias_desde_actualizacion <= 7);
            }
            
            // Clase CSS para filas según estado
            $clase_fila = '';
            if ($expira_pronto) {
                $clase_fila = 'table-warning';
            }
            if ($actualizado_reciente) {
                $clase_fila = 'table-success';
            }
            $csh ++;
            $domi="https://".$fila['dominio'];
            $html .= '
                                    <tr class="' . $clase_fila . '">
                                    <th>'.$csh.'</th>
                                        <td>
                                            <strong>' . htmlspecialchars($fila['dominio']) . '</strong>
                                            ' . ($expira_pronto ? '<i class="fas fa-exclamation-triangle text-warning ml-1" title="Expira pronto"></i>' : '') . '
                                        </td>
                                        <td><small>' . htmlspecialchars($fila['servidores']) . '</small></td>
                                        <td>' . date('d/m/Y', strtotime($fila['registered'])) . '</td>
                                        <td>
                                            ' . date('d/m/Y', strtotime($fila['expiration'])) . '
                                            <br><small class="text-muted">(' . $dias_restantes . ' días)</small>
                                        </td>
                                        <td>' . htmlspecialchars($fila['registrar']) . '</td>
                                        <td>' . htmlspecialchars($fila['type']) . '</td>
                                        <td>
                                            ' . ($fila['iscustomer'] == 'YES' ? 
                                                '<span class="badge badge-success"><i class="fas fa-check"></i> Sí</span>' : 
                                                '<span class="badge badge-secondary"><i class="fas fa-times"></i> No</span>') . '
                                        </td>
                                        <td>
                                            ' . ($fila['last_updated'] ? date('d/m/Y', strtotime($fila['last_updated'])) : '<span class="text-muted">Sin actualizar</span>') . '
                                            ' . ($actualizado_reciente ? '<i class="fas fa-check-circle text-success ml-1" title="Actualizado recientemente"></i>' : '') . '
                                        </td>
                                        <td>
                                            ' . (strlen($fila['NOTA']) > 50 ? 
                                                '<span title="' . htmlspecialchars($fila['NOTA']) . '">' . htmlspecialchars(substr($fila['NOTA'], 0, 50)) . '...</span>' : 
                                                htmlspecialchars($fila['NOTA'])) . '
                                        </td>
                                        <td>
                                            <form method="POST" style="display: inline;">
                                                <input type="hidden" name="actualizar_dominio" value="' . htmlspecialchars($fila['dominio']) . '">
                                                <button type="submit" class="btn btn-sm btn-outline-primary" 
                                                        title="Actualizar ' . htmlspecialchars($fila['dominio']) . '">
                                                    <i class="fas fa-sync-alt"></i>
                                                </button>
                                                <a href="'.$domi.'" target="_blank" class="btn  btn-sm btn-success"><i class="fa-solid fa-house"></i></a>

                                            </form>
                                        </td>
                                    </tr>';
        }
        
        $html .= '
                                </tbody>
                            </table>
                        </div>';
    } else {
        $html .= '
                        <div class="alert alert-info text-center">
                            <i class="fas fa-info-circle fa-2x mb-2"></i>
                            <h5>No se encontraron dominios</h5>
                            <p>No hay dominios que coincidan con los filtros seleccionados.</p>
                        </div>';
    }
    
    // Leyenda
    $html .= '
                        <div class="mt-3">
                            <h6><i class="fas fa-info-circle"></i> Leyenda:</h6>
                            <div class="row">
                                <div class="col-md-4">
                                    <small>
                                        <span class="badge badge-success">Verde</span> = Actualizado últimos 7 días
                                    </small>
                                </div>
                                <div class="col-md-4">
                                    <small>
                                        <span class="badge badge-warning">Amarillo</span> = Expira en menos de 30 días
                                    </small>
                                </div>
                                <div class="col-md-4">
                                    <small>
                                        <i class="fas fa-exclamation-triangle text-warning"></i> = Requiere atención
                                    </small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>';
    
    return $html;
} // generar_interfaz_dominios

// Ejemplo de uso:
/*
// Obtener parámetros de filtros
$solo_actualizados = isset($_GET['solo_actualizados']) && $_GET['solo_actualizados'] == '1';
$filtro_extension = isset($_GET['filtro_extension']) ? $_GET['filtro_extension'] : 'TODOS';

// Generar y mostrar la interfaz
$interfaz_html = generar_interfaz_dominios($link, $solo_actualizados, $filtro_extension);
echo $interfaz_html;

// Manejar el POST de actualización
if (isset($_POST['actualizar'])) {
    // Aquí llamarías a tu función de actualización existente
    // actualizar_dominios();
}
*/
function inicio(){
return "<!DOCTYPE html>
<html lang='es'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>
    <title>Control de Dominios</title>
    
    <!-- Bootstrap 4.6.2 CSS -->
    <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.2/css/bootstrap.min.css'>
    
    <!-- Font Awesome 6.4.0 -->
    <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css'>
    
    <!-- Estilos personalizados opcionales -->
    <style>
        body {
            background-color: #f8f9fa;
        }
        .card {
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            border: 1px solid rgba(0, 0, 0, 0.125);
        }
        .table th {
            border-top: none;
            font-size: 0.875rem;
        }
        .table td {
            font-size: 0.875rem;
            vertical-align: middle;
        }
        .badge {
            font-size: 0.75em;
        }
        .btn {
            border-radius: 0.25rem;
        }
    </style>
</head>
<body>
";
} // iicio
function esfinal(){
return "<!-- jQuery 3.6.4 -->
<script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js'></script>

<!-- Popper.js 1.16.1 (requerido para Bootstrap 4) -->
<script src='https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.16.1/umd/popper.min.js'></script>

<!-- Bootstrap 4.6.2 JavaScript -->
<script src='https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.2/js/bootstrap.min.js'></script>

</body>
</html>";
} // esfinal


function obtenerInfoDominioMX($dominio) {
    // Limpiar el dominio
    $dominio = strtolower(trim($dominio));
    
    // Validar que sea un dominio .mx o .com.mx
    if (!preg_match('/\.(mx|com\.mx)$/i', $dominio)) {
        return [
            'error' => true,
            'mensaje' => 'Este función solo es para dominios .mx y .com.mx'
        ];
    }
    
    // Realizar consulta WHOIS específica para México
    $datosWhois = consultarWhoisMX($dominio);
    
    if (!$datosWhois) {
        return [
            'error' => true,
            'mensaje' => 'No se pudo conectar al servidor WHOIS de México'
        ];
    }
    
    // Parsear los datos específicos del formato mexicano
    $info = parsearDatosMX($datosWhois);
    
    // Agregar el dominio consultado
    $info['dominio'] = $dominio;
    $info['error'] = false;
    
    $info['registrar']=trim($info['registrar']);
    
    $servidores= $info['ns1'] ?? '';
      $servidores.= ",". $info['ns2'] ?? '';
      $sql="update dominios2020 set servidores='$servidores',registered='".$info['fechaCreacion']."',
      expiration='".$info['fechaExpira']."',
      registrar='".$info['registrar']."',
      last_updated=now()
            
       where dominio='$dominio'";
    //   die($sql);
    
    // Formatear la respuesta
    //if ($info['registrar']=="Porkbun LLC"){
     //if ($dominio=='templotolteca.com.mx') die($sql);
       list($dummy)=avalues319($sql);

return sprintf(
        "||%s|%s|%s|%s|%s|%s|%s||",
        $dominio,
        $info['registrar'] ?? '',
        $info['fechaCreacion'] ?? '',
        $info['fechaUltimoCambio'] ?? '',
        $info['fechaExpira'] ?? '',
        $info['ns1'] ?? '',
        $info['ns2'] ?? ''
    );    
    //return $info;
}

/**
 * Realiza la consulta WHOIS específica para servidores mexicanos
 * @param string $dominio
 * @return string|false
 */
function consultarWhoisMX($dominio) {
    $servidor = 'whois.mx';
    $puerto = 43;
    $timeout = 15; // Más tiempo para servidores mexicanos
    
    // Crear conexión socket con manejo de errores mejorado
    $errno = 0;
    $errstr = '';
    $socket = @fsockopen($servidor, $puerto, $errno, $errstr, $timeout);
    
    if (!$socket) {
        // Intentar con IP directa como backup
        $ip = gethostbyname($servidor);
        if ($ip !== $servidor) {
            $socket = @fsockopen($ip, $puerto, $errno, $errstr, $timeout);
        }
        
        if (!$socket) {
            return false;
        }
    }
    
    // Configurar timeout para lectura
    stream_set_timeout($socket, $timeout);
    
    // Enviar consulta (formato específico para .mx)
    fwrite($socket, $dominio . "\r\n");
    
    // Leer respuesta completa
    $respuesta = '';
    $start_time = time();
    
    while (!feof($socket) && (time() - $start_time) < $timeout) {
        $line = fgets($socket, 1024);
        if ($line === false) break;
        $respuesta .= $line;
    }
    
    fclose($socket);
    
    // Convertir encoding si es necesario (servidores mexicanos usan ISO-8859-1)
    if (function_exists('mb_detect_encoding')) {
        $encoding = mb_detect_encoding($respuesta, ['UTF-8', 'ISO-8859-1', 'ASCII']);
        if ($encoding && $encoding !== 'UTF-8') {
            $respuesta = mb_convert_encoding($respuesta, 'UTF-8', $encoding);
        }
    }
    
    return $respuesta;
}

/**
 * Parsea los datos WHOIS específicos del formato mexicano
 * @param string $datos
 * @return array
 */
function parsearDatosMX($datos) {
    $info = [
        'registrar' => '',
        'fechaCreacion' => '',
        'fechaUltimoCambio' => '',
        'fechaExpira' => '',
        'ns1' => '',
        'ns2' => '',
        'nameservers' => []
    ];
    
    $lineas = explode("\n", $datos);
    $nameservers = [];
    $seccion_actual = '';
    
    foreach ($lineas as $linea) {
        $linea = trim($linea);
        
        // Saltar líneas vacías y comentarios
        if (empty($linea) || strpos($linea, '%') === 0 || strpos($linea, '#') === 0) {
            continue;
        }
        
        // Detectar secciones
        if (strpos($linea, ':') === false && !empty($linea)) {
            $seccion_actual = strtolower($linea);
            continue;
        }
        
        // Parsear líneas clave: valor
        if (strpos($linea, ':') !== false) {
            list($clave, $valor) = explode(':', $linea, 2);
            $clave = trim(strtolower($clave));
            $valor = trim($valor);
            
            switch ($clave) {
                // Fechas - múltiples formatos posibles
                case 'created on':
                case 'created':
                case 'creation date':
                    if (empty($info['fechaCreacion'])) {
                        $info['fechaCreacion'] = formatearFechaMX($valor);
                    }
                    break;
                    
                case 'last updated on':
                case 'last updated':
                case 'changed':
                case 'updated date':
                    if (empty($info['fechaUltimoCambio'])) {
                        $info['fechaUltimoCambio'] = formatearFechaMX($valor);
                    }
                    break;
                    
                case 'expiration date':
                case 'expires on':
                case 'expiry date':
                case 'registry expiry date':
                    if (empty($info['fechaExpira'])) {
                        $info['fechaExpira'] = formatearFechaMX($valor);
                    }
                    break;
                
                // Registrar - múltiples formatos
                case 'registrar':
                case 'sponsoring registrar':
                case 'registrant':
                    if (empty($info['registrar']) && !empty($valor)) {
                        $info['registrar'] = $valor;
                    }
                    break;
                
                // Name servers
                case 'name server':
                case 'nserver':
                case 'dns':
                case 'nameserver':
                    if (!empty($valor)) {
                        // Limpiar el nameserver (remover IPs si las hay)
                        $ns = explode(' ', $valor)[0];
                        $ns = strtolower(trim($ns));
                        if (!in_array($ns, $nameservers) && !empty($ns)) {
                            $nameservers[] = $ns;
                        }
                    }
                    break;
                    
                // URLs como registrar alternativo
                case 'url':
                case 'registrar url':
                    if (empty($info['registrar']) && !empty($valor)) {
                        // Extraer nombre del dominio de la URL
                        $parsed = parse_url($valor);
                        if (isset($parsed['host'])) {
                            $info['registrar'] = $parsed['host'];
                        }
                    }
                    break;
            }
        }
    }
    
    // Asignar nameservers
    $info['nameservers'] = $nameservers;
    if (count($nameservers) > 0) {
        $info['ns1'] = $nameservers[0];
    }
    if (count($nameservers) > 1) {
        $info['ns2'] = $nameservers[1];
    }
    
    return $info;
}

/**
 * Formatea fechas específicamente para el formato mexicano
 * @param string $fecha
 * @return string
 */
function formatearFechaMX($fecha) {
    $fecha = trim($fecha);
    
    // Limpiar texto extra común en servidores mexicanos
    $fecha = preg_replace('/\s+/', ' ', $fecha);
    $fecha = str_replace(['(', ')'], '', $fecha);
    
    // Formatos específicos comunes en servidores mexicanos
    $formatosMX = [
        'Y-m-d',                      // 2024-01-15
        'd-m-Y',                      // 15-01-2024
        'd/m/Y',                      // 15/01/2024
        'Y/m/d',                      // 2024/01/15
        'd-M-Y',                      // 15-Jan-2024
        'Y-m-d H:i:s',               // 2024-01-15 12:30:45
        'd-m-Y H:i:s',               // 15-01-2024 12:30:45
        'Y-m-d\TH:i:s',              // 2024-01-15T12:30:45
        'Y-m-d\TH:i:s\Z',            // 2024-01-15T12:30:45Z
        'D, d M Y',                   // Mon, 15 Jan 2024
        'd M Y',                      // 15 Jan 2024
        'M d, Y',                     // Jan 15, 2024
    ];
    
    foreach ($formatosMX as $formato) {
        $fechaObj = DateTime::createFromFormat($formato, $fecha);
        if ($fechaObj !== false) {
            return $fechaObj->format('Y-m-d');
        }
    }
    
    // Último recurso con strtotime
    $timestamp = strtotime($fecha);
    if ($timestamp !== false) {
        return date('Y-m-d', $timestamp);
    }
    
    // Si no se pudo parsear, devolver vacío
    return '';
}

?>
