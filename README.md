# Exploration C2 HTTP Beacon in Go

## Overview

This repository contains a small Go implementation of an HTTP beacon compatible with the Exploration C2 framework available at [Exploration C2](https://github.com/maxDcb/C2TeamServer).

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

## Testing

Unit tests cover handler registration, task execution, serialisation, and
command decoding behaviour:

```bash
go test ./...
```
