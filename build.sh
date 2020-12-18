#!/usr/bin/env sh
set -e
export GOPATH=`pwd`/bin
go get github.com/rakyll/statik
./bin/bin/statik -src deps
go build -o bin/pppoe-sim pppoe-sim
