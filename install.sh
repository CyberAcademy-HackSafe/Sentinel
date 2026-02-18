#!/bin/bash



echo "=============================================="

echo "     SentinelElite - Auto Installer"

echo "=============================================="



if [[ $EUID -ne 0 ]]; then

   echo "[!] Ejecuta con sudo: sudo ./install.sh"

   exit 1

fi



INSTALL_DIR="/opt/sentinel"



echo "[*] Instalando dependencias del sistema..."

apt update -y

apt install -y python3 python3-pip python3-venv nmap exploitdb



echo "[*] Actualizando base de datos Searchsploit..."

searchsploit -u



echo "[*] Creando directorio en $INSTALL_DIR ..."

mkdir -p $INSTALL_DIR



echo "[*] Copiando archivos..."

cp sentinel.py $INSTALL_DIR/

cp requirements.txt $INSTALL_DIR/



echo "[*] Creando entorno virtual..."

python3 -m venv $INSTALL_DIR/venv



echo "[*] Instalando dependencias Python..."

$INSTALL_DIR/venv/bin/pip install --upgrade pip

$INSTALL_DIR/venv/bin/pip install -r $INSTALL_DIR/requirements.txt



echo "[*] Configurando permisos..."

chmod +x $INSTALL_DIR/sentinel.py



echo "[*] Creando comando global..."

cat <<EOF > /usr/local/bin/sentinel

#!/bin/bash

sudo $INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/sentinel.py "\$@"

EOF



chmod +x /usr/local/bin/sentinel



echo ""

echo "=============================================="

echo "      INSTALACION COMPLETADA CON EXITO"

echo "=============================================="

echo ""

echo "Ahora puedes usar la herramienta así:"

echo ""

echo "   sudo sentinel example.com"

echo ""
