<div align="center">
  <h1>ChxChx Security</h1>
  <p><strong>Privacidad de red por proceso y modo global opcional para Linux.</strong><br>Usa Tor donde tú lo decides o enruta todo el equipo de forma explícita y con fallo cerrado.</p>
  <p>
    <a href="https://github.com/chxchx-dev/chxchx-security-ip/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/chxchx-dev/chxchx-security-ip/ci.yml?branch=main&amp;label=CI" alt="CI"></a>
    <img src="https://img.shields.io/badge/estado-Alpha-orange" alt="Estado Alpha">
    <img src="https://img.shields.io/badge/sistema-Linux-blue" alt="Linux">
    <img src="https://img.shields.io/badge/Python-3.11%2B-blue" alt="Python 3.11 o posterior">
    <a href="LICENSE"><img src="https://img.shields.io/github/license/chxchx-dev/chxchx-security-ip" alt="Licencia MIT"></a>
  </p>
  <p>
    <a href="#instalación">Instalar</a> ·
    <a href="#primeros-pasos">Primeros pasos</a> ·
    <a href="#comandos">Comandos</a> ·
    <a href="#seguridad-y-límites">Seguridad</a>
  </p>
</div>

> [!WARNING]
> **Versión Alpha 0.2.0.** La instalación recomendada descarga desde <code>main</code>. La rama mutable <code>dev</code> recibe mejoras en desarrollo antes de integrarse; puede cambiar sin aviso. La integración privilegiada en una VM desechable y las instalaciones limpias por distribución siguen pendientes.

## ¿Qué es ChxChx Security?

Una herramienta de terminal para Fedora, Ubuntu y Kali Linux. Coordina Tor, <code>torsocks</code>, NetworkManager, namespaces y <code>nftables</code> para que puedas elegir qué aplicación ejecutas por una ruta protegida.

**Por defecto no crea un túnel global:** iniciar Tor no cambia la conexión de todo el equipo. Se protegen los programas que lanzas expresamente mediante <code>chxsec run</code>, <code>chxsec shell</code> o una sesión aislada. El **modo global** es una acción explícita que redirige todo el tráfico del host por Tor con un kill switch de <code>nftables</code>.

## Cómo funciona

```mermaid
flowchart LR
    U[Usuario] --> CLI[chxsec]
    CLI -->|run o shell| TS[torsocks]
    TS --> TOR[Servicio Tor]
    CLI -->|session start| NS[Namespace Linux]
    NS --> FW[Firewall nftables]
    FW --> PORTS[TransPort y DNSPort de Tor]
    FW -. Otro tráfico .-> DROP[Descartado]
    CLI -->|global start| GNAT[nftables NAT del host]
    GNAT --> PORTS
    GNAT -. UDP, ICMP e IPv6 .-> DROP
```

## Instalación

Los instaladores preparan un entorno Python en <code>~/.local/share/chxchx-security</code> y pueden instalar Python, Tor, <code>torsocks</code>, NetworkManager, <code>iproute</code>/<code>iproute2</code> y <code>nftables</code>. No requieren Docker. Descarga el script primero y ejecútalo desde la terminal; evita <code>curl | bash</code>.

| Distribución | Requisitos | Instalador |
| --- | --- | --- |
| Fedora | DNF · Python 3.11+ | [Descargar instalador](https://github.com/chxchx-dev/chxchx-security-ip/raw/refs/heads/main/install-remote-fedora.sh?download=1) |
| Ubuntu 24.04 o posterior | APT · Python 3.11+ | [Descargar instalador](https://github.com/chxchx-dev/chxchx-security-ip/raw/refs/heads/main/install-remote-debian.sh?download=1) |
| Kali Linux actual | APT · Python 3.11+ | [Descargar instalador](https://github.com/chxchx-dev/chxchx-security-ip/raw/refs/heads/main/install-remote-debian.sh?download=1) |

[Descargar el código fuente (.tar.gz)](https://github.com/chxchx-dev/chxchx-security-ip/archive/refs/heads/main.tar.gz)

### Fedora

~~~bash
curl --fail --location --show-error --retry 3 --connect-timeout 20 --max-time 120 \
  --output install-chxsec-fedora.sh \
  https://raw.githubusercontent.com/chxchx-dev/chxchx-security-ip/main/install-remote-fedora.sh
bash install-chxsec-fedora.sh
~~~

### Ubuntu y Kali Linux

~~~bash
curl --fail --location --show-error --retry 3 --connect-timeout 20 --max-time 120 \
  --output install-chxsec-debian.sh \
  https://raw.githubusercontent.com/chxchx-dev/chxchx-security-ip/main/install-remote-debian.sh
bash install-chxsec-debian.sh
~~~

El instalador pregunta antes de añadir paquetes del sistema. Para aceptar esa instalación sin la pregunta, ejecuta el script con <code>--yes</code>.

### Al terminar

~~~bash
source ~/.local/share/chxchx-security/.venv/bin/activate
chxsec doctor
chxsec
~~~

<code>doctor</code> revisa el sistema y <code>chxsec</code> abre el menú guiado. **Tor no se inicia durante la instalación.**

## Primeros pasos

### Menú interactivo

Ejecuta <code>chxsec</code> desde una terminal. El menú te permite volver después de cada acción:

| Opción | Acción |
| --- | --- |
| 1 | Revisar dependencias y estado del sistema |
| 2–5 | Iniciar, detener, consultar y verificar Tor |
| 6 | Abrir una shell protegida |
| 7 | Ver perfiles de NetworkManager |
| 8 | Ejecutar un comando protegido |
| 9 | Abrir la guía de comandos |
| 10 | Activar el modo global (todo el host por Tor) |
| 11 | Cambiar la IP de salida con una nueva identidad de Tor |
| 12 | Desactivar el modo global |
| 13 | Consultar el estado del modo global |
| 0 | Salir |

Sin una terminal interactiva, <code>chxsec</code> muestra la ayuda de la CLI.

### Ejecutar una aplicación mediante Tor

~~~bash
chxsec tor start
chxsec tor verify
chxsec run -- curl https://example.com
chxsec tor stop
~~~

<code>run</code> protege solo el comando indicado. La verificación oculta la IP de salida de forma predeterminada; usa <code>chxsec tor verify --reveal-ip</code> para mostrarla expresamente.

> [!NOTE]
> Tor permanece activo al salir del menú porque es un servicio compartido del sistema. <code>chxsec tor stop</code> también desconecta las otras aplicaciones que estén usando Tor.

### Cambiar la IP de salida

~~~bash
chxsec tor new-identity
chxsec tor new-identity --restart
~~~

<code>new-identity</code> pide un circuito nuevo por la interfaz de control de Tor y comprueba si cambió la IP de salida. Si el puerto o socket de control no está disponible, <code>--restart</code> reinicia <code>tor.service</code> como alternativa. Las IP se ocultan por defecto; añade <code>--reveal-ip</code> si quieres verlas. Una identidad nueva no garantiza una IP distinta: Tor puede reutilizar el mismo nodo de salida.

El cliente busca la interfaz de control en <code>/run/tor/control</code> y, si no existe, en <code>127.0.0.1:9051</code>. Puedes ajustarlo con <code>CHXSEC_TOR_CONTROL_SOCKET</code>, <code>CHXSEC_TOR_CONTROL_HOST</code>, <code>CHXSEC_TOR_CONTROL_PORT</code> y <code>CHXSEC_TOR_CONTROL_COOKIE</code>; la contraseña, si la usas, se lee de <code>CHXSEC_TOR_CONTROL_PASSWORD</code> y nunca se escribe en logs. En Fedora, el usuario debe pertenecer al grupo <code>toranon</code> para leer la cookie; en Debian/Kali, a <code>debian-tor</code>.

<code>chxsec run</code>, <code>chxsec shell</code> y el modo global arrancan Tor automáticamente si está parado. Para impedirlo, define <code>CHXSEC_AUTO_START_TOR=0</code>.

### Modo global: todo el host por Tor

> [!CAUTION]
> El modo global redirige **todo** el tráfico del equipo, no solo el de <code>chxsec</code>. Requiere <code>sudo</code>, <code>nftables</code> y que Tor se ejecute como un usuario distinto de root. Actívalo solo en un equipo que controles y, preferiblemente, en una VM desechable con snapshot.

~~~bash
# Revisar el plan y las reglas sin cambiar nada.
chxsec global plan

# Aplicar; el comando pide sudo y arranca Tor si está parado.
chxsec global start --yes

# Alternativa para conservar el acceso a la LAN (por ejemplo, impresoras o NAS).
chxsec global start --yes --allow-lan

# Consultar y desactivar.
chxsec global status
chxsec global stop
~~~

El modo global es **fail-closed**:

- Todo el TCP del host se redirige al <code>TransPort</code> de Tor y el DNS UDP/53 a su <code>DNSPort</code>.
- UDP que no sea DNS, ICMP e IPv6 se descartan. Tor no transporta UDP ni ICMP.
- Solo el tráfico local, el propio proceso de Tor y DHCP quedan exentos. La LAN se bloquea salvo que uses <code>--allow-lan</code>.
- Si no se puede determinar el UID de Tor o Tor corre como root, el modo global se niega a aplicarse para evitar un bucle de redirección.
- Si falla la validación de <code>nftables</code>, la recarga de Tor o el estado, se intenta revertir lo aplicado.

El plan se puede revisar antes de ejecutar; <code>global start</code> sin <code>--yes</code> solo simula. Los cambios se aplican en el host y no sobreviven a un reinicio: vuelve a ejecutar <code>chxsec global start --yes</code> después de arrancar. La configuración de Tor vive en <code>/etc/tor/torrc.d/chxsec-global.conf</code> y el estado en <code>/run/chxsec/global.json</code>; <code>chxsec global stop</code> los retira junto con las tablas <code>nftables</code>. Las tablas se llaman <code>chxsec_global_nat</code> y <code>chxsec_global_filter</code>.

> [!WARNING]
> Mientras el modo global esté activo, las actualizaciones, videollamadas, juegos y otras aplicaciones que dependen de UDP o ICMP dejarán de funcionar. Si prefieres proteger solo ciertos procesos, usa <code>chxsec run</code>, <code>chxsec shell</code> o una sesión aislada en lugar del modo global.

### Cambiar la política MAC

~~~bash
chxsec mac list
chxsec mac apply "Mi WiFi" random
~~~

Aplicar una política cambia el perfil seleccionado en NetworkManager. Añade <code>--reconnect</code> solo si puedes permitir que se interrumpa la conexión.

## Comandos

| Quiero… | Comando |
| --- | --- |
| Comprobar preparación del sistema | <code>chxsec doctor</code> |
| Obtener el diagnóstico en JSON | <code>chxsec doctor --json</code> |
| Consultar el servicio Tor | <code>chxsec tor status</code> |
| Iniciar o detener Tor | <code>chxsec tor start</code> · <code>chxsec tor stop</code> |
| Comprobar la ruta Tor | <code>chxsec tor verify</code> |
| Cambiar la IP de salida | <code>chxsec tor new-identity</code> |
| Revisar el modo global sin cambios | <code>chxsec global plan</code> |
| Enrutar todo el host por Tor | <code>chxsec global start --yes</code> |
| Desactivar el modo global | <code>chxsec global stop</code> |
| Consultar el modo global | <code>chxsec global status</code> |
| Ejecutar una aplicación compatible | <code>chxsec run -- &lt;comando&gt;</code> |
| Abrir una shell temporal protegida | <code>chxsec shell</code> |
| Consultar perfiles de red | <code>chxsec mac list</code> |
| Revisar herramientas para sesiones | <code>chxsec session tools</code> |

<code>run</code> y <code>shell</code> dependen de una aplicación compatible con Tor por TCP. Para aislamiento adicional, usa una sesión de red.

## Sesiones de red aisladas

Una sesión crea un namespace con firewall de denegación por defecto y listeners Tor privados. Su tráfico TCP y DNS se redirige a Tor; el resto, incluido IPv6, se descarta.

> [!CAUTION]
> Estas opciones modifican recursos de red del sistema. Primero revisa el plan. Prueba los cambios privilegiados en una VM desechable con snapshot.

~~~bash
# Revisar herramientas y plan; no aplica cambios.
chxsec session tools
chxsec session plan demo

# Simular la sesión completa.
chxsec session start demo -- curl https://example.com

# Aplicar los cambios privilegiados y ejecutar el comando.
chxsec session start --yes demo -- curl https://example.com
~~~

La sesión completa elimina sus recursos cuando el comando termina, también al interrumpirlo con Ctrl-C. Si aplicas las etapas manualmente, guarda el identificador y ejecuta <code>chxsec session destroy &lt;id&gt;</code> al terminar. Aún no hay un comando para listar sesiones; [RECOVERY.md](RECOVERY.md) explica cómo recuperarse si la limpieza falla.

## Seguridad y límites

| ChxChx Security hace | No hace |
| --- | --- |
| Ejecuta mediante Tor procesos compatibles que eliges explícitamente. | No activa el modo global por su cuenta: requiere <code>global start --yes</code>. |
| Con el modo global, redirige todo el host y descarta UDP, ICMP e IPv6 por defecto. | No transporta UDP ni ICMP por Tor; esas aplicaciones dejan de funcionar en modo global. |
| Falla si no encuentra el listener SOCKS; no usa una conexión directa como alternativa. | No garantiza anonimato ni elimina rastros del sistema. |
| En sesiones aisladas, bloquea protocolos fuera de las reglas de Tor. | <code>run</code> no protege UDP ni aplicaciones que evadan <code>torsocks</code>. |
| Oculta identificadores locales e IP pública en las salidas predeterminadas. | No oculta huellas del navegador, cuentas, cookies, WebRTC o telemetría. |

Para navegación anónima, usa Tor Browser. Un navegador normal no se vuelve anónimo solo por ejecutarse mediante un proxy.

El programa no guarda registros de ejecución por defecto ni recopila el nombre de usuario o el hostname. <code>doctor</code> y <code>mac list</code> ocultan identificadores locales; <code>tor verify</code> oculta la IP salvo que pidas mostrarla.

## Actualizar o desinstalar

### Actualizar

Descarga otra vez el instalador de tu distribución y ejecútalo. Por defecto sigue <code>main</code> y reemplaza los archivos instalados; no ofrece rollback automático. La rama <code>dev</code> recibe mejoras en desarrollo antes de integrarse en <code>main</code>; úsala solo si quieres probar esos cambios.

### Desinstalar

Destruye primero cualquier sesión manual pendiente. Luego elimina el directorio de la herramienta:

~~~bash
chxsec session destroy <id>
rm -rf -- "$HOME/.local/share/chxchx-security"
~~~

El segundo comando elimina solo los archivos de ChxChx Security; no desinstala Tor, NetworkManager ni otros paquetes del sistema. Si cambiaste <code>XDG_DATA_HOME</code> o <code>CHXSEC_INSTALL_DIR</code>, sustituye la ruta por la ubicación exacta.

<details>
<summary><strong>Instalar desde una copia local, fijar una versión o desarrollar</strong></summary>

### Instalar desde un checkout

~~~bash
# Fedora
./install-fedora.sh --yes

# Ubuntu o Kali
./install-debian.sh --yes

source .venv/bin/activate
chxsec doctor
~~~

Usa <code>--dry-run</code> para revisar las acciones del instalador local. <code>--no-system-packages</code> omite la instalación de paquetes del sistema cuando ya están presentes.

### Fijar una referencia del código fuente

Los bootstraps aceptan una etiqueta de release o un SHA completo de 40 caracteres. Para fijar una referencia, configura también el SHA-256 del archivo descargado:

~~~bash
export CHXSEC_SOURCE_REF="<etiqueta vX.Y.Z o commit de 40 caracteres>"
export CHXSEC_SOURCE_ARCHIVE_SHA256="<SHA-256 del archivo fuente>"
bash install-chxsec-fedora.sh
~~~

Reemplaza ambos valores de ejemplo. El bootstrap comprueba el SHA-256 antes de extraer el código.

Para probar la versión en desarrollo en lugar de la instalación recomendada, puedes seleccionar explícitamente su archivo fuente:

En Ubuntu o Kali, sustituye `install-chxsec-fedora.sh` por `install-chxsec-debian.sh`.

~~~bash
CHXSEC_SOURCE_ARCHIVE_URL="https://github.com/chxchx-dev/chxchx-security-ip/archive/refs/heads/dev.tar.gz" \
  bash install-chxsec-fedora.sh
~~~

### Ejecutar pruebas y build

~~~bash
./install-fedora.sh --yes --with-dev
source .venv/bin/activate
pytest
python -m build --sdist --wheel
~~~

La matriz CI cubre Fedora, Ubuntu 24.04 y Kali rolling, además de Python 3.11 y 3.13. La integración privilegiada de namespaces, firewall y Tor sigue pendiente de ejecutarse en una VM Fedora desechable.

</details>

## Licencia

Distribuido bajo la [Licencia MIT](LICENSE).
