#!/bin/bash



if [[ $EUID -ne 0 ]]; then

   echo "Ejecuta con sudo."

   exit 1

fi



echo "[*] Eliminando Sentinel..."



rm -rf /opt/sentinel

rm -f /usr/local/bin/sentinel



echo "[✓] Sentinel eliminado correctamente."
