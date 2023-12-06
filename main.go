package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type PublicKey struct {
	p, g, b *big.Int
}

type KeyPair struct {
	private *big.Int
	public  PublicKey
}

type EncryptedMessage struct {
	x *big.Int
	y *big.Int
}

func GenKeys() *KeyPair {
	res := new(KeyPair)
	res.public.p, _ = rand.Prime(rand.Reader, 2048)
	res.public.g, _ = rand.Int(rand.Reader, res.public.p)
	res.private, _ = rand.Int(rand.Reader, res.public.p)
	t := new(big.Int)
	t = t.Exp(res.public.g, res.private, res.public.p)
	res.public.b = t
	return res
}

func Encrypt(M string, key PublicKey) (res EncryptedMessage) {
	ar := make([]byte, len(M))
	for i, ch := range M {
		ar[i] = byte(ch)
	}
	t := new(big.Int).SetBytes(ar)

	k, _ := rand.Int(rand.Reader, key.p)

	x := new(big.Int)
	x.Exp(key.g, k, key.p)
	res.x = x

	y := new(big.Int)
	y.Exp(key.b, k, key.p)
	res.y = y

	res.y.Mul(res.y, t)
	res.y.Mod(res.y, key.p)
	return res
}

func Decrypt(M EncryptedMessage, keys KeyPair) (res string) {
	s := new(big.Int)
	s.Exp(M.x, keys.private, keys.public.p)
	s.ModInverse(s, keys.public.p)
	t := new(big.Int)
	t.Mul(M.y, s)
	t.Mod(t, keys.public.p)

	res = ""
	for _, ch := range t.Bytes() {
		res += string(ch)
	}

	return res
}

func main() {
	keys := GenKeys()
	encM := Encrypt("Hello, World!", keys.public)

	fmt.Println(Decrypt(encM, *keys))

	/*keys.public.p.Add(keys.public.p, new(big.Int).SetInt64(5))
	fmt.Println(Decrypt(encM, *keys))

	keys.public.p.Add(keys.public.p, new(big.Int).SetInt64(-5))
	fmt.Println(Decrypt(encM, *keys))

	keys.private.Add(keys.private, new(big.Int).SetInt64(17))
	fmt.Println(Decrypt(encM, *keys))

	keys.private.Add(keys.private, new(big.Int).SetInt64(-17))
	fmt.Println(Decrypt(encM, *keys))*/
}
