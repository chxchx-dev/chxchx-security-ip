```text
   ██████╗██╗  ██╗██╗  ██╗ ██████╗██╗  ██╗██╗  ██╗
  ██╔════╝██║  ██║╚██╗██╔╝██╔════╝██║  ██║╚██╗██╔╝
  ██║     ███████║ ╚███╔╝ ██║     ███████║ ╚███╔╝
  ██║     ██╔══██║ ██╔██╗ ██║     ██╔══██║ ██╔██╗
  ╚██████╗██║  ██║██╔╝ ██╗╚██████╗██║  ██║██╔╝ ██╗
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝

              C H X C H X   S E C U R I T Y

               PRIVACY • SECURITY • CONTROL

                      by @chxchx-dev

                [ SYSTEM STATUS: SECURED ]
```

# ChxChx Security v0.2.0

Herramienta de privacidad y seguridad para la terminal de Fedora, Ubuntu y Kali Linux. Permite ejecutar programas compatibles a través de Tor, comprobar la conexión Tor, reducir metadatos locales accidentales y administrar opciones de privacidad MAC de NetworkManager.

No promete volver invisible el equipo ni borrar rastros forenses. Solo protege los procesos que el usuario ejecuta explícitamente con la herramienta y dentro de los límites descritos más abajo.

## Para qué sirve

- Comprobar dependencias y preparación del sistema con `chxsec doctor`, sin imprimir usuario, hostname, números de serie ni MAC permanentes.
- Iniciar, consultar y verificar el servicio Tor con `chxsec tor`.
- Ejecutar programas compatibles mediante Tor con `chxsec run -- <comando>`.
- Abrir una shell temporal protegida con `chxsec shell`, sin guardar historial de esa shell.
- Consultar o cambiar las políticas MAC clonadas de NetworkManager.
- Ejecutar un comando dentro de una sesión de red aislada con namespace, firewall nftables de denegación por defecto y listener Tor privado mediante `chxsec session start`.
- Revisar resultados de preparación y verificación en JSON, por ejemplo con `chxsec doctor --json`.

La herramienta coordina Tor y utilidades existentes del sistema. No incluye criptografía propia ni implementa un proxy propio. La configuración es opcional; los valores predeterminados funcionan sin archivo `.env`.

## Límite de protección

ChxChx Security puede reducir la exposición de la IP pública para aplicaciones TCP compatibles que se ejecuten explícitamente a través de la herramienta. No anonimiza automáticamente todos los procesos del equipo. UDP, aplicaciones enlazadas estáticamente, aplicaciones aisladas, huellas del navegador, plugins, sesiones de cuenta, cookies, WebRTC, telemetría y comportamiento todavía pueden identificar al usuario.

Para navegar de forma anónima, usa Tor Browser. Un navegador normal no se vuelve anónimo solo por usar un proxy.

## Instalación

Los instaladores preparan un entorno Python local en `~/.local/share/chxchx-security` cuando se descargan desde GitHub. No usan Docker, contenedores ni volúmenes montados. Piden confirmación antes de instalar paquetes del sistema; `sudo` puede pedir la contraseña.

### Fedora

[Descargar instalador para Fedora](https://github.com/chxchx-dev/chxchx-security/raw/refs/heads/dev/install-remote-fedora.sh?download=1) · [Descargar código fuente `.tar.gz`](https://github.com/chxchx-dev/chxchx-security/archive/refs/heads/dev.tar.gz)

En la terminal de Fedora, descarga y ejecuta el instalador en dos pasos:

```bash
curl --fail --location --show-error --retry 3 --connect-timeout 20 --max-time 120 \
  --output install-chxsec-fedora.sh \
  https://raw.githubusercontent.com/chxchx-dev/chxchx-security/dev/install-remote-fedora.sh
bash install-chxsec-fedora.sh
```

El instalador muestra el progreso de descarga, usa un tiempo máximo y luego descarga el código fuente y prepara el entorno. Ejecutarlo desde un archivo permite que la pregunta de confirmación y `sudo` lean desde la terminal; no lo canalices con `curl | bash`. Para aceptar la instalación de paquetes sin confirmación, añade `--yes`:

```bash
bash install-chxsec-fedora.sh --yes
```

### Ubuntu y Kali Linux

Ubuntu 24.04 o posterior y Kali Linux actual comparten APT y requieren Python 3.11 o posterior, así que usan el mismo instalador:

[Descargar instalador para Ubuntu](https://github.com/chxchx-dev/chxchx-security/raw/refs/heads/dev/install-remote-debian.sh?download=1) · [Descargar instalador para Kali Linux](https://github.com/chxchx-dev/chxchx-security/raw/refs/heads/dev/install-remote-debian.sh?download=1) · [Descargar código fuente `.tar.gz`](https://github.com/chxchx-dev/chxchx-security/archive/refs/heads/dev.tar.gz)

Descárgalo y ejecútalo desde una terminal de Ubuntu o Kali:

```bash
curl --fail --location --show-error --retry 3 --connect-timeout 20 --max-time 120 \
  --output install-chxsec-debian.sh \
  https://raw.githubusercontent.com/chxchx-dev/chxchx-security/dev/install-remote-debian.sh
bash install-chxsec-debian.sh
```

Este instalador detecta Ubuntu o Kali, muestra el progreso al descargar y prepara Python, Tor, torsocks, NetworkManager, iproute2 y nftables con APT. También instala el proyecto en un `.venv` local. Para saltar la confirmación de paquetes, usa:

```bash
bash install-chxsec-debian.sh --yes
```

Cuando termine cualquiera de los instaladores, activa el entorno:

```bash
source ~/.local/share/chxchx-security/.venv/bin/activate
chxsec doctor
chxsec tor verify
```

Los enlaces directos apuntan a la rama `dev`. Puedes usar otro archivo fuente con `CHXSEC_SOURCE_ARCHIVE_URL` o elegir otra carpeta con `CHXSEC_INSTALL_DIR`.

### Instalar desde una copia local

Desde un checkout de Fedora:

```bash
./install-fedora.sh --yes
source .venv/bin/activate
chxsec doctor
```

Desde un checkout de Ubuntu o Kali:

```bash
./install-debian.sh --yes
source .venv/bin/activate
chxsec doctor
```

Usa `--dry-run` para revisar las acciones previstas sin cambiar el sistema. El instalador no inicia ni habilita Tor salvo que se pida expresamente con `--start-tor` o `--enable-tor`. La configuración es opcional: los ajustes pueden ir en `.env` o en variables `CHXSEC_*`; no subas archivos `.env` al repositorio.

## Ejemplos

```bash
chxsec doctor
chxsec doctor --json
chxsec tor status
chxsec tor verify
chxsec tor verify --json
chxsec run -- curl https://example.com
chxsec shell
chxsec mac list
chxsec mac list --reveal-identifiers
chxsec mac apply "My WiFi" random
chxsec session tools
chxsec session plan demo
chxsec session network-plan demo --subnet 10.203.0.0/30
chxsec session tor-port-plan 10.203.0.1
chxsec session firewall-plan demo --subnet 10.203.0.0/30
chxsec session network-apply demo --subnet 10.203.0.0/30        # simulación
chxsec session network-apply demo --subnet 10.203.0.0/30 --yes  # privilegiado
chxsec session firewall-apply demo --subnet 10.203.0.0/30        # simulación
chxsec session firewall-apply demo --subnet 10.203.0.0/30 --yes  # privilegiado
chxsec session tor-port-apply demo --subnet 10.203.0.0/30        # simulación
chxsec session tor-port-apply demo --subnet 10.203.0.0/30 --yes  # privilegiado
chxsec session start demo -- curl https://example.com          # simulación
chxsec session start --yes demo -- curl https://example.com    # privilegiado
chxsec session destroy demo
```

En `session start`, escribe el comando después de `--`. Por cómo se capturan los argumentos restantes, coloca todas las opciones (`--subnet`, `--yes`, `--json`, etc.) antes del identificador de sesión.

Aplicar una política MAC modifica el perfil de conexión seleccionado en NetworkManager. Añade `--reconnect` solo si estás preparado para que la conexión se interrumpa y vuelva a conectarse.

## Valores predeterminados de seguridad

- No se guardan registros de ejecución por defecto.
- No se recopilan el nombre de usuario ni el hostname.
- No se guardan las IP públicas detectadas.
- La verificación Tor oculta la IP salvo que se use expresamente `--reveal-ip`.
- `mac list` oculta SSID y nombres de interfaces locales salvo que se use `--reveal-identifiers`.
- Las comprobaciones directas de IP están desactivadas por defecto.
- Los cambios de red del sistema son explícitos y usan las herramientas existentes.

Los comandos JSON devuelven código de salida `0` solo si todas las comprobaciones solicitadas pasan. Si falla la preparación o la verificación, devuelven `1`.

## Garantías y límites de seguridad

- La ejecución protegida se niega a iniciar si el listener SOCKS de Tor no está disponible; no cambia a una conexión directa.
- La verificación Tor resuelve el hostname de comprobación por SOCKS y requiere que el endpoint confirme `IsTor`.
- La protección se aplica a procesos TCP compatibles que se ejecutan explícitamente con la herramienta; no protege todo el equipo.
- El proyecto no borra registros del sistema, auditorías ni historiales de terceros.
- `session plan` solo muestra una simulación: no crea namespaces ni cambia reglas del firewall.
- `session network-plan` solo prepara el plan. `session network-apply --yes` es el primer comando privilegiado: crea el namespace y un par veth con direcciones, sin instalar rutas ni reglas de firewall. Si falla, revierte los recursos creados. Sin `--yes`, solo muestra los comandos. `session destroy` elimina el namespace y el veth.
- `session tor-port-plan` solo muestra las directivas privadas `TransPort` y `DNSPort`. `session tor-port-apply --yes` escribe una configuración por sesión en `/etc/tor/torrc.d`, la valida con `tor --verify-config`, recarga Tor (no lo reinicia) y confirma que escucha en la dirección de gateway de la sesión. Si algo falla, revierte los cambios. Requiere que la interfaz ya esté conectada mediante `network-apply`. En sistemas con SELinux enforcing, registra los puertos configurados como `tor_port_t` con `semanage port` antes de escribir el archivo; los desregistra con `session destroy`. Ejecuta siempre `session destroy`: una configuración sobrante puede impedir que Tor arranque después de reiniciar el equipo; `doctor` también la detecta. El `DNSPort` predeterminado es 5300 porque mDNS suele ocupar 5353.
- `session firewall-plan` muestra las reglas nftables de denegación por defecto sin aplicarlas. `session firewall-apply --yes` las valida con `nft -c` y las instala de forma atómica en dos tablas limitadas a la interfaz veth de esa sesión. Se niega a ejecutarse dos veces y no modifica otras tablas ni interfaces. `session destroy` elimina las tablas, el namespace y el veth.
- `session start --yes <id> -- <comando>` coordina la sesión: conecta el namespace, instala el firewall y el listener Tor en ese orden, desactiva IPv6 dentro del namespace y añade la única ruta de la sesión a través del gateway. Luego ejecuta el comando como el usuario que inició la herramienta, sin privilegios elevados. El firewall redirige el tráfico TCP y DNS de ese namespace a Tor y descarta los demás protocolos, incluido IPv6. La limpieza se ejecuta al terminar el comando, también con Ctrl-C; si falla una etapa de preparación, revierte lo que alcanzó a crear.
- No publiques capturas ni registros de terminal que muestren SSID, usuarios, hostnames, rutas personales, IP o nombres de interfaces.

## Desarrollo

```bash
./install-fedora.sh --yes --with-dev
source .venv/bin/activate
pytest
python -m build --sdist --wheel
```

Las pruebas de integración con Fedora y Tor están desactivadas por defecto porque requieren un servicio Tor en ejecución y acceso a Internet:

```bash
make integration
```

La prueba completa del ciclo de namespaces cambia la red y las reglas del firewall. Ejecútala solo en una máquina virtual desechable con Fedora, nunca en el equipo de uso diario:

```bash
make namespace-integration
```
