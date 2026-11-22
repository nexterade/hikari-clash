#!/bin/sh
# Build ulang bin/hikari-stats untuk Android arm64 (butuh Go >= 1.22, tanpa dependensi lain).
#   sh build.sh          arm64 (HP)
#   sh build.sh test     jalankan unit test lalu build
set -e
cd "$(dirname "$0")/src"
[ "$1" = "test" ] && go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o ../bin/hikari-stats .
echo "OK: bin/hikari-stats"
