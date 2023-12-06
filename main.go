package main

import (
	"crypto/rand"
	"crypto/sha256"
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
	x, y *big.Int
}

type Signature struct {
	r, s *big.Int
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

func SignMessage(M string, keys KeyPair) (res Signature) {
	mod := new(big.Int)
	mod.Sub(keys.public.p, new(big.Int).SetInt64(1))

	k := new(big.Int)
	for {
		k, _ = rand.Int(rand.Reader, mod)
		if k.ModInverse(k, mod) != nil {
			break
		}
	}
	r := new(big.Int)
	r.Exp(keys.public.g, k, keys.public.p)
	res.r = r

	k.ModInverse(k, mod)
	h := sha256.Sum256([]byte(M))

	t := new(big.Int)
	t.Mul(keys.private, r)
	t.Sub(new(big.Int).SetBytes(h[:]), t)
	t.Mod(t, mod)
	t.Mul(t, k)
	t.Mod(t, mod)
	res.s = t

	return res
}

func Verify(M string, key PublicKey, signature Signature) bool {
	h := sha256.Sum256([]byte(M))

	br := new(big.Int)
	br.Exp(key.b, signature.r, key.p)

	rs := new(big.Int)
	rs.Exp(signature.r, signature.s, key.p)

	u := new(big.Int)
	u.Mul(br, rs)
	u.Mod(u, key.p)

	gm := new(big.Int)
	gm.Exp(key.g, new(big.Int).SetBytes(h[:]), key.p)

	return gm.Cmp(u) == 0
}

func main() {
	m := "Hello, World!"
	keys := GenKeys()
	encM := Encrypt(m, keys.public)

	fmt.Println(Decrypt(encM, *keys))

	keys.public.p.Add(keys.public.p, new(big.Int).SetInt64(5)) //damaged p
	fmt.Println(Decrypt(encM, *keys))

	keys.public.p.Add(keys.public.p, new(big.Int).SetInt64(-5))
	fmt.Println(Decrypt(encM, *keys))

	keys.private.Add(keys.private, new(big.Int).SetInt64(17)) //damaged private key
	fmt.Println(Decrypt(encM, *keys))

	keys.private.Add(keys.private, new(big.Int).SetInt64(-17))
	fmt.Println(Decrypt(encM, *keys))

	signature := SignMessage(m, *keys)

	fmt.Println(Verify(m, keys.public, signature))
	fmt.Println(Verify("hElLo, wOrLd!", keys.public, signature)) //another message same signature
}
