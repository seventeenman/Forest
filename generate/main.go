package main

import (
	b64 "encoding/base64"
	"fmt"
	"os"
	"strconv"
)

type Cipher struct {
	s    [256]uint32
	i, j uint8
}

type KeySizeError int

var iniPath = "./frpc.ini"

func main() {
	RC4_Key := []byte("f379cfd7a55b621577a8389d1817a102")
	key, _ := NewCipher(RC4_Key)

	RandomData, _ := os.ReadFile(iniPath)

	buf := make([]byte, len(RandomData))
	for i, v := range RandomData {
		buf[i] = byte(v)
	}

	key.XorKeyStreamGeneric(buf, buf)

	buf = []byte(b64.StdEncoding.EncodeToString(buf))
	fmt.Println("[+] Payload: ")
	fmt.Println(" -e " + string(buf))
}

func (k KeySizeError) Error() string {
	return "crypto/rc4: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (*Cipher, error) {
	k := len(key)
	if k < 1 || k > 256 {
		return nil, KeySizeError(k)
	}
	var c Cipher
	for i := 0; i < 256; i++ {
		c.s[i] = uint32(i)
	}
	var j uint8 = 0
	for i := 0; i < 256; i++ {

		j += uint8(c.s[i]) + key[i%k]

		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return &c, nil
}

func (c *Cipher) Reset() {
	for i := range c.s {
		c.s[i] = 0
	}
	c.i, c.j = 0, 0
}

func (c *Cipher) XorKeyStreamGeneric(dst, src []byte) {
	i, j := c.i, c.j
	for k, v := range src {
		i += 1
		j += uint8(c.s[i])
		c.s[i], c.s[j] = c.s[j], c.s[i]
		dst[k] = v ^ uint8(c.s[uint8(c.s[i]+c.s[j])])
	}
	c.i, c.j = i, j
}
