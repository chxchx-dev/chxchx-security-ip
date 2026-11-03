# ChxChx Security

**Herramienta de terminal para Linux que ayuda a ejecutar aplicaciones compatibles a través de Tor y a crear sesiones de red aisladas.**

<p>
  <strong>Versión:</strong> 0.2.0 Alpha ·
  <strong>Sistemas:</strong> Fedora, Ubuntu y Kali Linux ·
  <strong>Licencia:</strong> MIT
</p>

> **Estado Alpha:** los instaladores públicos siguen la rama mutable <code>dev</code>; esta versión todavía no se considera una release validada. La integración privilegiada en una VM desechable y las instalaciones limpias por distribución siguen pendientes.

## Qué ofrece

ChxChx Security reúne herramientas existentes de Linux para que puedas comprobar y controlar qué procesos usan una ruta de red a través de Tor. No incluye criptografía ni un proxy propios: coordina Tor, <code>torsocks</code>, NetworkManager, namespaces y <code>nftables</code>.

| Función | Uso |
| --- | --- |
| Revisar requisitos y estado local | <code>chxsec doctor</code> |
| Iniciar, detener y comprobar Tor | <code>chxsec tor</code> |
| Ejecutar un programa compatible mediante Tor | <code>chxsec run -- &lt;comando&gt;</code> |
| Abrir una shell temporal mediante Tor | <code>chxsec shell</code> |
| Preparar una sesión de red aislada | <code>chxsec session</code> |
| Consultar o cambiar la política MAC de NetworkManager | <code>chxsec mac</code> |
| Abrir el menú guiado | <code>chxsec</code> |

## Cómo se usa

~~~text
ChxChx Security
      │
      ├── Comprueba el sistema: doctor
      ├── Prepara Tor: tor start / tor verify
      └── Ejecuta solo el proceso elegido:
             run, shell o session start
~~~

Iniciar Tor no cambia la conexión de todo el equipo ni activa una “IP cifrada” global. La protección se aplica únicamente a los procesos que ejecutas expresamente mediante la herramienta.

## Sistemas compatibles

| Distribución | Requisitos principales |
| --- | --- |
| Fedora | Python 3.11 o posterior; instalador con DNF |
| Ubuntu 24.04 o posterior | Python 3.11 o posterior; instalador con APT |
| Kali Linux actual | Python 3.11 o posterior; instalador con APT |

Los instaladores preparan un entorno Python local en <code>~/.local/share/chxchx-security</code> y pueden instalar Tor, <code>torsocks</code>, NetworkManager, <code>iproute2</code> y <code>nftables</code>. Solicitan confirmación antes de instalar paquetes del sistema; <code>--yes</code> permite aceptar esa instalación sin la pregunta interactiva.

## Instalación rápida

Descarga el instalador como archivo y luego ejecútalo desde una terminal. No lo canalices directamente con <code>curl | bash</code>.

[Instalador Fedora](https://github.com/chxchx-dev/chxchx-security/raw/refs/heads/dev/install-remote-fedora.sh?download=1) · [Instalador Ubuntu y Kali](https://github.com/chxchx-dev/chxchx-security/raw/refs/heads/dev/install-remote-debian.sh?download=1) · [Código fuente](https://github.com/chxchx-dev/chxchx-security/archive/refs/heads/dev.tar.gz)

### Fedora

~~~bash
curl --fail --location --show-error --retry 3 --connect-timeout 20 --max-time 120 \
  --output install-chxsec-fedora.sh \
  https://raw.githubusercontent.com/chxchx-dev/chxchx-security/dev/install-remote-fedora.sh
bash install-chxsec-fedora.sh
~~~

### Ubuntu y Kali Linux

~~~bash
curl --fail --location --show-error --retry 3 --connect-timeout 20 --max-time 120 \
  --output install-chxsec-debian.sh \
  https://raw.githubusercontent.com/chxchx-dev/chxchx-security/dev/install-remote-debian.sh
bash install-chxsec-debian.sh
~~~

Al terminar:

~~~bash
source ~/.local/share/chxchx-security/.venv/bin/activate
chxsec doctor
chxsec
~~~

El primer comando comprueba las dependencias. El último abre el menú interactivo; Tor no se inicia automáticamente al instalar.

También puedes revisar las acciones del instalador sin cambiar el sistema usando <code>--dry-run</code>. Para omitir la confirmación de paquetes, pasa <code>--yes</code> al instalador:

~~~bash
bash install-chxsec-fedora.sh --dry-run
bash install-chxsec-fedora.sh --yes
~~~

Ubuntu y Kali usan <code>install-chxsec-debian.sh</code> en los ejemplos.

## Menú y ciclo de Tor

Cuando <code>chxsec</code> se ejecuta en una terminal, muestra un menú en español con acciones para:

1. Revisar el sistema.
2. Iniciar Tor.
3. Detener Tor, con confirmación.
4. Consultar el estado del servicio.
5. Verificar la ruta Tor.
6. Abrir una shell protegida.
7. Consultar perfiles de NetworkManager.
8. Ejecutar un comando protegido.
9. Consultar ejemplos de comandos.

Si no hay una terminal interactiva, <code>chxsec</code> muestra la ayuda de la CLI. Al ejecutar un comando desde el menú, la herramienta separa sus argumentos sin pasarlos a un shell.

Salir del menú **no detiene Tor**. Es un servicio del sistema que puede estar usando otra aplicación. Deténlo de forma explícita con la opción 3 o con:

~~~bash
chxsec tor stop
~~~

Detener Tor interrumpe también las aplicaciones que dependan de ese servicio. Para una operación puntual, comprueba si Tor ya está en uso antes de detenerlo.

## Comandos habituales

~~~bash
chxsec doctor
chxsec doctor --json
chxsec tor status
chxsec tor start
chxsec tor verify
chxsec tor stop
chxsec run -- curl https://example.com
chxsec shell
chxsec mac list
chxsec mac apply "Mi WiFi" random
~~~

La verificación oculta la IP detectada de forma predeterminada. Usa <code>chxsec tor verify --reveal-ip</code> solo si quieres mostrarla expresamente.

Aplicar una política MAC modifica el perfil seleccionado en NetworkManager. Añade <code>--reconnect</code> solo si estás preparado para que la conexión se interrumpa y se vuelva a conectar.

## Sesiones aisladas

Las sesiones avanzadas combinan un namespace de red, un par virtual <code>veth</code>, reglas de firewall y listeners Tor privados. Primero puedes ver los requisitos y el plan sin aplicar cambios:

~~~bash
chxsec session tools
chxsec session plan demo
chxsec session network-plan demo --subnet 10.203.0.0/30
chxsec session firewall-plan demo --subnet 10.203.0.0/30
chxsec session tor-port-plan 10.203.0.1
~~~

Para ejecutar una aplicación en una sesión completa:

~~~bash
# Simula y muestra las acciones, sin aplicarlas.
chxsec session start demo -- curl https://example.com

# Aplica la configuración privilegiada y ejecuta el comando.
chxsec session start --yes demo -- curl https://example.com
~~~

En estos comandos, escribe la aplicación después de <code>--</code>. Coloca las opciones como <code>--yes</code>, <code>--json</code> o <code>--subnet</code> antes del identificador de sesión.

Las etapas manuales también admiten simulación. Añade <code>--yes</code> para aplicar los cambios privilegiados:

~~~bash
chxsec session network-apply demo --subnet 10.203.0.0/30
chxsec session network-apply demo --subnet 10.203.0.0/30 --yes
chxsec session firewall-apply demo --subnet 10.203.0.0/30 --yes
chxsec session tor-port-apply demo --subnet 10.203.0.0/30 --yes
chxsec session destroy demo
~~~

La herramienta solo retira recursos que reconoce como creados por la sesión. <code>session start</code> limpia al finalizar el comando o al recibir Ctrl-C. Para las etapas manuales, guarda el identificador y ejecuta <code>session destroy &lt;id&gt;</code> al terminar; todavía no existe un comando para listar todas esas sesiones. Consulta [RECOVERY.md](RECOVERY.md) si la limpieza falla.

## Modelo de seguridad y límites

- No protege automáticamente todos los programas ni toda la conexión del equipo.
- <code>run</code> y <code>shell</code> requieren aplicaciones compatibles con Tor por TCP. UDP, aplicaciones enlazadas estáticamente y configuraciones que evadan el proxy pueden quedar fuera de esa protección.
- Para navegación anónima, usa Tor Browser. Un navegador normal no se vuelve anónimo solo por usar un proxy.
- Las sesiones aisladas aplican un firewall de denegación por defecto: encaminan TCP y DNS a Tor y descartan el resto del tráfico, incluido IPv6.
- La ejecución protegida falla si el listener SOCKS no está disponible; no continúa por una conexión directa.
- Los comandos de planificación son simulaciones. Las acciones del sistema requieren una confirmación explícita mediante <code>--yes</code> cuando corresponda.
- <code>session network-apply</code> crea el namespace, el enlace virtual y el resolver de DNS de la sesión; por sí solo no instala rutas ni firewall.
- <code>session tor-port-apply</code> requiere la interfaz creada por <code>network-apply</code>, agrega configuración privada de Tor y recarga el servicio. En sistemas con SELinux puede registrar etiquetas de puertos que deben limpiarse mediante <code>session destroy</code>.
- No borra registros del sistema, historiales ni rastros forenses.
- <code>doctor</code> y <code>mac list</code> ocultan por defecto los identificadores locales; la verificación Tor oculta la IP pública. No se recopilan el usuario ni el hostname y no se guardan registros de ejecución por defecto.

La herramienta puede reducir la exposición de la IP pública para procesos concretos; no garantiza anonimato. Huellas del navegador, cuentas, cookies, plugins, WebRTC, telemetría y comportamiento pueden revelar la identidad.

## Actualización, fijado de versión y desinstalación

Los instaladores remotos apuntan actualmente a <code>dev</code>. Volver a ejecutar el instalador actualiza los archivos y puede sobrescribir la instalación anterior; no hay rollback automático. Conserva una copia si necesitas volver a tu versión previa.

Para fijar la descarga a una release o a un commit, define la referencia y el SHA-256 del archivo fuente antes de ejecutar el instalador:

~~~bash
export CHXSEC_SOURCE_REF="<etiqueta vX.Y.Z o SHA completo de 40 caracteres>"
export CHXSEC_SOURCE_ARCHIVE_SHA256="<SHA-256 del archivo .tar.gz>"
bash install-chxsec-fedora.sh
~~~

Sustituye los dos valores de ejemplo. Ambas variables son obligatorias para una referencia fijada. El instalador verifica el checksum antes de extraer el código. También acepta la URL del archivo en <code>CHXSEC_SOURCE_ARCHIVE_URL</code> y una ruta de instalación personalizada en <code>CHXSEC_INSTALL_DIR</code>.

Antes de desinstalar, destruye las sesiones manuales que hayas creado y confirma la ruta de instalación. Para la ubicación predeterminada:

~~~bash
chxsec session destroy <id>
rm -rf -- "$HOME/.local/share/chxchx-security"
~~~

Esto elimina los archivos de la herramienta, no Tor, NetworkManager ni los paquetes del sistema. Si usaste otra ubicación, sustituye la ruta por el directorio exacto. La configuración es opcional; no subas archivos <code>.env</code> al repositorio.

## Desarrollo y validación

~~~bash
./install-fedora.sh --yes --with-dev
source .venv/bin/activate
pytest
python -m build --sdist --wheel
~~~

La última suite local registrada (2 de noviembre de 2026) terminó con **133 pruebas pasadas y 7 omitidas**. Las pruebas opt-in de integración requieren Tor y conectividad. La prueba completa de namespaces modifica la red y el firewall: ejecútala únicamente en una VM Fedora desechable con snapshot:

~~~bash
make namespace-integration
~~~

Siguen pendientes la validación privilegiada en esa VM, las instalaciones limpias del artefacto exacto en Fedora, Ubuntu y Kali, y la confirmación de CI en GitHub. Por eso esta Alpha no debe considerarse una release validada.

## Licencia

Distribuido bajo la licencia [MIT](LICENSE).
