package elgamal

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"gopkg.in/mgo.v2/bson"
)

// PublicKey represents an ElGamal public key.
type PublicKey struct {
	G, P, Y *big.Int
}

func (pub *PublicKey) Encrypt(msg []byte, random io.Reader) (cypher *Cypher, err error) {
	m := new(big.Int).SetBytes(msg)

	k, err := rand.Int(random, pub.P)
	if err != nil {
		return
	}

	c1 := new(big.Int).Exp(pub.G, k, pub.P)
	s := new(big.Int).Exp(pub.Y, k, pub.P)

	c2 := s.Mul(s, m)
	c2.Mod(c2, pub.P)
	cypher = &Cypher{c1, c2, pub.P}
	return
}

func (this *PublicKey) GetBSON() (interface{}, error) {
	return bson.D{
		{"g", fmt.Sprintf("%x", this.G)},
		{"p", fmt.Sprintf("%x", this.P)},
		{"y", fmt.Sprintf("%x", this.Y)},
	}, nil
}

// PrivateKey represents an ElGamal private key.
type PrivateKey struct {
	PublicKey
	X *big.Int
}

func (this *PrivateKey) GetBSON() (interface{}, error) {
	return bson.D{
		{"x", fmt.Sprintf("%x", this.X)},
		{"g", fmt.Sprintf("%x", this.G)},
		{"p", fmt.Sprintf("%x", this.P)},
		{"y", fmt.Sprintf("%x", this.Y)},
	}, nil
}

func (priv *PrivateKey) Decrypt(cypher *Cypher) (msg []byte) {
	s := new(big.Int).Exp(cypher.C1, priv.X, priv.P)
	s.ModInverse(s, priv.P)
	s.Mul(s, cypher.C2)
	s.Mod(s, priv.P)
	em := s.Bytes()
	return em
}

type Cypher struct {
	C1, C2, P *big.Int
}

func (this *Cypher) GetBSON() (interface{}, error) {
	return bson.D{
		{"c1", fmt.Sprintf("%x", this.C1)},
		{"c2", fmt.Sprintf("%x", this.C2)},
		{"p", fmt.Sprintf("%x", this.P)},
	}, nil
}

func (this *Cypher) Mul(cypher1, cypher2 *Cypher) *Cypher {
	this.C1 = new(big.Int).Mod(new(big.Int).Mul(cypher1.C1, cypher2.C1), cypher1.P)
	this.C2 = new(big.Int).Mod(new(big.Int).Mul(cypher1.C2, cypher2.C2), cypher1.P)
	this.P = cypher1.P
	return this
}

func (this *Cypher) ToJSON() map[string]string {
	return map[string]string{
		"C1": fmt.Sprintf("%x", this.C1),
		"C2": fmt.Sprintf("%x", this.C2),
		"P":  fmt.Sprintf("%x", this.P),
	}
}

func (this *Cypher) MarshalJSON() ([]byte, error) {
	return json.Marshal(this.ToJSON())
}

func (this *Cypher) UnmarshalJSON(bytes []byte) error {
	m := make(map[string]string)
	err := json.Unmarshal(bytes, &m)
	if err != nil {
		return err
	}
	this.FromJSON(m)
	return nil
}

func (this *Cypher) FromJSON(json map[string]string) (*Cypher, error) {
	var err error
	this.C1, err = fromHex(json["C1"])
	if err != nil {
		return nil, err
	}
	this.C2, err = fromHex(json["C2"])
	if err != nil {
		return nil, err
	}
	this.P, err = fromHex(json["P"])
	if err != nil {
		return nil, err
	}
	return this, err
}

func fromHex(hex string) (*big.Int, error) {
	n, err := new(big.Int).SetString(hex, 16)
	if !err {
		msg := fmt.Sprintf("Cannot convert %s to int as hexadecimal", hex)
		return nil, errors.New(msg)
	}
	return n, nil
}
