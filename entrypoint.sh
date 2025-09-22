#!/bin/sh

set -e
set -u

: "${PUID:=0}"
: "${PGID:=${PUID}}"

if [ "$#" = 0 ]; then
    set -- "$(command -v bash 2>/dev/null || command -v sh)" -l
fi

if [ "$PUID" != 0 ]
then
    groupadd --gid $PGID worker 2>/dev/null || true
    useradd --uid $PUID --gid $PGID --shell "$(command -v bash 2>/dev/null || command -v sh)" -d "$(pwd)" worker 2>/dev/null || true

    if [ -d "/run/secrets" ]; then
        mkdir -p secrets
        cp /run/secrets/* secrets/
        chown -R "${PUID}:${PGID}" .
    fi
    set -- gosu "${PUID}:${PGID}" "${@}"
fi

exec "$@"
