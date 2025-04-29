# go-charm

A tiny, self-contained cryptography library, implementing authenticated encryption and keyed hashing.

This is a port to Go. It has to be fully compatible with the C, Zig and JavaScript (TypeScript) versions.

## Install

```sh
go get -u "github.com/x13a/go-charm"
```

## Usage

```go
package main

import (
	"crypto/rand"
	"fmt"
	
	"github.com/x13a/go-charm"
)

func randomBytes(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}

func main() {
	msg := []byte("Hello, World!")

	var c *charm.Charm
	var err error
	
	key := make([]byte, charm.KeyLength)
	err = randomBytes(key)
	if err != nil {
		panic(err)
	}

	// Nonce is optional
	nonce := make([]byte, charm.NonceLength)
	err = randomBytes(nonce)
	if err != nil {
		panic(err)
	}
	
	// Encrypt
	c, err = charm.NewCharm(key, nonce)
	if err != nil {
		panic(err)
	}
	tag := c.Encrypt(msg)
	
	// Decrypt
	c, err = charm.NewCharm(key, nonce)
	if err != nil {
		panic(err)
	}
	err = c.Decrypt(msg, tag)
	if err != nil {
		panic(err)
	}

	// Hash
	c, err = charm.NewCharm(key, nonce)
	if err != nil {
		panic(err)
	}
	hash := c.Hash(msg)
	fmt.Printf("%x\n", hash)
}
```

## Other implementations

- [charm](https://github.com/jedisct1/charm) original implementation in C
- [zig-charm](https://github.com/jedisct1/zig-charm) an implementation of Charm in the Zig language
- [charm.js](https://github.com/jedisct1/charm.js) an implementation of Charm in the JavaScript (TypeScript) language

## License

MIT
