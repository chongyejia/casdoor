#!/bin/bash

# Database settings: environment variables override conf/app.conf
# (see conf/conf.go, os.LookupEnv). Previously this script exported
# driverName=sqlite / dataSourceName=file:casdoor.db whenever the env vars
# were unset, which silently replaced the database configured in a mounted
# conf/app.conf with an empty local SQLite file.
#
# Only fall back to SQLite when there is no conf/app.conf at all. If the
# config file exists (baked into the image or mounted), leave the env vars
# unset so conf/app.conf is authoritative.
if [ ! -f /conf/app.conf ] && [ ! -f ./conf/app.conf ]; then
  if [ -z "${driverName:-}" ]; then
    echo "docker-entrypoint: conf/app.conf not found, defaulting driverName=sqlite" >&2
    export driverName=sqlite
  fi
  if [ -z "${dataSourceName:-}" ]; then
    echo "docker-entrypoint: conf/app.conf not found, defaulting to local SQLite file" >&2
    export dataSourceName="file:casdoor.db?cache=shared"
  fi
fi

exec /server
