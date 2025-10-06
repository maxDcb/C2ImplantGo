# Exploration C2 HTTP Beacon in Go

## Overview

This repository provides a Go re-implementation of the educational
[`maxDcb/C2ImplantPy`](https://github.com/maxDcb/C2ImplantPy) project. It reproduces the implant behaviour of the
Python version while remaining compatible with the
[Exploration C2](https://github.com/maxDcb/C2TeamServer) server.

The project contains two main packages:

* `beacon`: Implements the core implant logic (task handling, command
  execution, encoding/decoding helpers, network enumeration utilities, etc.).
* `cmd/beacon`: A tiny CLI that continuously performs HTTP(S) beacon
  check-ins using the embedded listener configuration.

## Requirements

* Go 1.22 or newer
* Unix-like operating system (the current implementation focuses on Linux
  semantics for process and network enumeration)

## Usage

Build the command-line beacon:

```bash
go build ./cmd/beacon
```

Run the beacon, specifying the controller host, port, and scheme:

```bash
./beacon <host> <port> <http|https>
```

The binary reuses the embedded HTTP listener profile from the original Python
implant. For HTTPS endpoints the TLS certificate is not verified, mimicking the
behaviour of the upstream project.

## Testing

Unit tests cover handler registration, task execution, serialisation, and
command decoding behaviour:

```bash
go test ./...
```

## Disclaimer

This repository is intended for educational exploration of command and control
concepts. Use responsibly and only in lab environments where you have explicit
permission to operate.
