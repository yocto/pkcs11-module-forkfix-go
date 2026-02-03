# PKCS#11 ForkFix Module

[![Go](https://github.com/yocto/pkcs11-module-forkfix-go/actions/workflows/go.yml/badge.svg)](https://github.com/yocto/pkcs11-module-forkfix-go/actions/workflows/go.yml)

A PKCS#11 module which fixes the runtime after a process fork.

## Usage

Fork, clone or download this repository and use it as base for your own PKCS#11 module.

## Build

To build this module, you just run:

```shell
make build
```

Note: Because of Cgo, `gcc` is expected to be installed.

## Environment variables

- `PKCS11_SUBMODULE` - An absolute path to the real PKCS#11 module to load.