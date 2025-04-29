package charm

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	TagLength   = 16
	KeyLength   = 32
	NonceLength = 16
	HashLength  = 32
)

var (
	roundConstants = [12]uint32{
		0x058, 0x038, 0x3c0, 0x0d0, 0x120, 0x014,
		0x060, 0x02c, 0x380, 0x0f0, 0x1a0, 0x012,
	}

	ErrInvalidKeyLen   = errors.New("invalid key length")
	ErrInvalidNonceLen = errors.New("invalid nonce length")
	ErrInvalidTagLen   = errors.New("invalid tag length")
	ErrTagVerifyFail   = errors.New("tag verification failed")
)

type xoodoo struct {
	state [12]uint32
}

func newXoodoo(buf []byte) *xoodoo {
	x := &xoodoo{}
	x.readBytes(buf)
	return x
}

func (x *xoodoo) writeBytes(dst []byte) {
	for i := 0; i < len(dst)/4; i++ {
		binary.LittleEndian.PutUint32(dst[i*4:], x.state[i])
	}
}

func (x *xoodoo) readBytes(src []byte) {
	for i := 0; i < len(src)/4; i++ {
		x.state[i] = binary.LittleEndian.Uint32(src[i*4:])
	}
}

func rot32(x uint32, n int) uint32 {
	return bits.RotateLeft32(x, 32-n)
}

func (x *xoodoo) permute() {
	st := &x.state
	var e [4]uint32
	for r := 0; r < len(roundConstants); r++ {
		for i := 0; i < 4; i++ {
			e[i] = rot32(st[i]^st[i+4]^st[i+8], 18)
			e[i] ^= rot32(e[i], 9)
		}
		for i := 0; i < len(st); i++ {
			st[i] ^= e[(i-1)&3]
		}
		st[7], st[4] = st[4], st[7]
		st[7], st[5] = st[5], st[7]
		st[7], st[6] = st[6], st[7]
		st[0] ^= roundConstants[r]
		for i := 0; i < 4; i++ {
			a := st[i]
			b := st[i+4]
			c := rot32(st[i+8], 21)
			st[i+8] = rot32((b&^a)^c, 24)
			st[i+4] = rot32((a&^c)^b, 31)
			st[i] ^= c &^ b
		}
		st[8], st[10] = st[10], st[8]
		st[9], st[11] = st[11], st[9]
	}
}

func (x *xoodoo) squeezePermute() []byte {
	buf := make([]byte, 16)
	x.writeBytes(buf)
	x.permute()
	return buf
}

type Charm struct {
	x *xoodoo
}

func NewCharm(key []byte, nonce []byte) (*Charm, error) {
	if len(key) != KeyLength {
		return nil, ErrInvalidKeyLen
	}
	if nonce != nil && len(nonce) != NonceLength {
		return nil, ErrInvalidNonceLen
	}
	buf := make([]byte, NonceLength+KeyLength)
	if nonce != nil {
		copy(buf, nonce)
	}
	copy(buf[NonceLength:], key)
	c := &Charm{x: newXoodoo(buf)}
	c.x.permute()
	return c, nil
}

func xor128(dst, src []byte) {
	for i := 0; i < 16; i++ {
		dst[i] ^= src[i]
	}
}

func (c *Charm) Encrypt(msg []byte) []byte {
	squeezed := make([]byte, 16)
	buf := make([]byte, 16)
	padded := make([]byte, 16+1)
	off := 0
	for ; off+16 <= len(msg); off += 16 {
		mc := msg[off : off+16]
		c.x.writeBytes(buf)
		copy(squeezed, buf)
		xor128(buf, mc)
		xor128(mc, squeezed)
		c.x.readBytes(buf)
		c.x.permute()
	}
	leftover := len(msg) - off
	copy(padded, msg[off:])
	padded[leftover] = 0x80
	c.x.writeBytes(buf)
	copy(squeezed, buf)
	xor128(buf, padded)
	c.x.readBytes(buf)
	c.x.state[11] ^= (1 << 24) | (uint32(leftover) >> 4 << 25) | (1 << 26)
	xor128(padded, squeezed)
	copy(msg[off:], padded[:leftover])
	c.x.permute()
	return c.x.squeezePermute()
}

func (c *Charm) Decrypt(msg []byte, expectedTag []byte) error {
	if len(expectedTag) != TagLength {
		return ErrInvalidTagLen
	}
	squeezed := make([]byte, 16)
	buf := make([]byte, 16)
	padded := make([]byte, 16+1)
	off := 0
	for ; off+16 <= len(msg); off += 16 {
		mc := msg[off : off+16]
		c.x.writeBytes(buf)
		copy(squeezed, buf)
		xor128(mc, squeezed)
		xor128(buf, mc)
		c.x.readBytes(buf)
		c.x.permute()
	}
	leftover := len(msg) - off
	copy(padded, msg[off:])
	c.x.writeBytes(buf)
	copy(squeezed[:leftover], buf[:leftover])
	memzero(squeezed[leftover:])
	xor128(padded, squeezed)
	padded[leftover] = 0x80
	xor128(buf, padded)
	c.x.readBytes(buf)
	c.x.state[11] ^= (1 << 24) | (uint32(leftover) >> 4 << 25) | (1 << 26)
	copy(msg[off:], padded[:leftover])
	c.x.permute()
	tag := c.x.squeezePermute()
	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		memzero(msg)
		return ErrTagVerifyFail
	}
	return nil
}

func (c *Charm) Hash(msg []byte) []byte {
	buf := make([]byte, 16)
	padded := make([]byte, 16+1)
	off := 0
	for ; off+16 <= len(msg); off += 16 {
		c.x.writeBytes(buf)
		xor128(buf, msg[off:off+16])
		c.x.readBytes(buf)
		c.x.permute()
	}
	leftover := len(msg) - off
	copy(padded, msg[off:])
	padded[leftover] = 0x80
	c.x.writeBytes(buf)
	xor128(buf, padded)
	c.x.readBytes(buf)
	c.x.state[11] ^= (1 << 24) | (uint32(leftover) >> 4 << 25)
	c.x.permute()
	h := make([]byte, HashLength)
	copy(h[:16], c.x.squeezePermute())
	copy(h[16:], c.x.squeezePermute())
	return h
}

func memzero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
