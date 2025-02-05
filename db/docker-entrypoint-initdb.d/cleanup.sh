#!/bin/bash
set -e

#psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
#	CREATE USER docker;
#	CREATE DATABASE docker;
#	GRANT ALL PRIVILEGES ON DATABASE docker TO docker;
#EOSQL



# PostgreSQL 서버가 완전히 시작될 때까지 기다리기
until pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do
  echo "Waiting for PostgreSQL to be ready..."
  sleep 2
done

#psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f /migration/init.sql
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /migration/init.sql

echo "init.sql done..."