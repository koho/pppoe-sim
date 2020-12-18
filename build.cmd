@echo off
go get github.com/rakyll/statik || exit /b 1
statik -src deps || exit /b 1
go build -o bin/pppoe-sim.exe pppoe-sim