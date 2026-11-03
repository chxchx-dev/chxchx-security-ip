# Recuperar una sesión tras un error

Usa esta guía si `chxsec session destroy` falla, `session start` informa que la limpieza quedó incompleta o el equipo se apagó mientras una sesión manual seguía activa.

Los comandos de abajo están limitados a recursos de ChxChx. No borres otros namespaces, tablas del firewall, configuración de Tor ni etiquetas SELinux adivinando sus nombres.

## Encontrar IDs de sesiones

Los comandos manuales crean recursos con nombres que empiezan por `chxsec-`. Este comando muestra candidatos que aún aparecen asociados a namespaces o a archivos de configuración de Tor:

```bash
{
  sudo ip netns list | awk '$1 ~ /^chxsec-/ { sub(/^chxsec-/, "", $1); print $1 }'
  sudo find /etc/tor/torrc.d -maxdepth 1 -type f -name 'chxsec-*.conf' -printf '%f\n' 2>/dev/null \
    | sed -e 's/^chxsec-//' -e 's/\.conf$//'
} | sort -u
```

Si conservas la salida de `network-apply`, `firewall-apply`, `tor-port-apply` o `session start`, también puedes usar el valor que aparece después de `session=`. El CLI todavía no guarda un registro de sesiones. Si solo queda una tabla nftables y perdiste su ID, detente: el nombre de esa tabla no permite reconstruirlo con seguridad.

El prefijo `chxsec-` ayuda a encontrar candidatos, pero no demuestra quién creó un namespace. Destruye únicamente un ID que reconozcas como una sesión tuya de ChxChx. Si no puedes confirmarlo, no ejecutes `destroy`.

## Limpiar una sesión identificada

Ejecuta `destroy` para cada ID confirmado:

```bash
chxsec session destroy <id>
```

El comando intenta quitar el drop-in de Tor, las tablas nftables de esa sesión, el namespace y su par veth, y el archivo resolver del namespace cuando aún conserva el marcador de propiedad de ChxChx. La limpieza de SELinux se limita a los puertos que el drop-in marca como creados por esa sesión. El comando muestra el resultado de Tor, firewall y namespace. Conserva el ID y la salida completa si algún resultado indica un fallo.

`session start` normalmente limpia al terminar el proceso, también con Ctrl-C. Para `network-apply`, `firewall-apply` y `tor-port-apply`, conserva el ID hasta que `session destroy` termine correctamente.

## Si la limpieza falla

1. Conserva la instalación; `chxsec doctor` puede detectar drop-ins de sesión que quedaron en Tor.
2. Si sigue existiendo un drop-in de Tor sin una sesión activa, resuelve la limpieza antes de reiniciar: esa configuración sobrante puede impedir que Tor arranque.
3. Si ocurrió en una VM desechable de pruebas y no puedes confirmar que quedó limpia, vuelve a su snapshot inicial.
4. En un equipo que usas, conserva el ID y la salida completa y contacta al mantenedor. No ejecutes comandos amplios de `ip`, `nft`, `rm` o `semanage` contra nombres supuestos.

La herramienta no elimina registros del sistema ni configuraciones de red ajenas. La recuperación se limita a recursos que puede identificar para el ID indicado.
