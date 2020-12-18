#!/usr/bin/env sh
go get github.com/rakyll/statik
statik -src deps
go build -o bin/pppoe-sim.exe pppoe-sim
