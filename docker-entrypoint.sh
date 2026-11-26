#!/bin/sh
set -eu

if [ "$(id -u)" = 0 ]; then
  data=/app/data
  if [ "${ANTICRASH_ENABLED:-true}" != false ] && [ ! -L "$data" ]; then
    if mkdir -p "$data" && chown node:node "$data" && chmod u+rwx "$data"; then
      case "${ANTICRASH_DB_PATH:-}" in
        ''|./data/anticrash.sqlite) database="$data/anticrash.sqlite" ;;
        /app/data/*)
          filename=${ANTICRASH_DB_PATH#/app/data/}
          case "$filename" in
            ''|.|..|*/*) database= ;;
            *) database="$data/$filename" ;;
          esac ;;
        *) database= ;;
      esac
      if [ -n "$database" ]; then
        for file in "$database" "$database-wal" "$database-shm" "$database-journal"; do
          if [ -f "$file" ] && [ ! -L "$file" ]; then
            if ! { chown node:node "$file" && chmod u+rw "$file"; }; then
              echo "Антикраш: не удалось подготовить права на $file" >&2
            fi
          fi
        done
      fi
    else
      echo "Антикраш: хранилище $data недоступно на запись. Проверь права тома." >&2
    fi
  fi
  exec su-exec node:node "$@"
fi

exec "$@"
