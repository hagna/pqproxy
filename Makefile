#!/usr/bin/make -f

build: main.go internal
	./build

release: build
	GOOS=darwin GOARCH=amd64 ./build -o pqproxy_darwin_amd64
	GOOS=windows GOARCH=amd64 ./build -o pqproxy_windows_amd64
	GOOS=linux GOARCH=arm ./build -o pqproxy_linux_arm

install: build
	go install
