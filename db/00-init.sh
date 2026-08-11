#!/bin/bash
# Ejecuta init.sql.template con APP_DB_PASSWORD inyectada como variable de
# psql (no como texto plano interpolado a mano), usando la sintaxis
# ":'variable'" que psql escapa/quotea automáticamente como literal SQL.
# Se corre automáticamente al crear el contenedor de Postgres por primera
# vez (docker-entrypoint-initdb.d), como el usuario superusuario definido
# en POSTGRES_USER.
set -euo pipefail

if [ -z "${APP_DB_PASSWORD:-}" ]; then
    echo "ERROR: falta la variable de entorno APP_DB_PASSWORD (definila en .env)." >&2
    exit 1
fi

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -v app_db_password="$APP_DB_PASSWORD" \
     -f /docker-entrypoint-initdb.d/init.sql.template
