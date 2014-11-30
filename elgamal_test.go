package elgamal

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"reflect"
	"testing"

	"bitbucket.org/ustraca/crypto"
)

// This is the 1024-bit MODP group from RFC 5114, section 2.1:
const primeHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D" +
	"23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACC" +
	"BDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC" +
	"8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"

const generatorHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CF" +
	"F14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F" +
	"4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D" +
	"18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

func fromSafeHex(s string) *big.Int {
	ret, err := crypto.FromHex(s)
	if err != nil {
		panic(err)
	}
	return ret
}

func TestEncryptDecrypt(t *testing.T) {
	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: fromSafeHex(generatorHex),

			P: fromSafeHex(primeHex),
		},
		X: fromSafeHex("42"),
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	message := []byte("hello world")
	cypher, err := priv.PublicKey.Encrypt(message, rand.Reader)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}
	message2 := priv.Decrypt(cypher)
	if !bytes.Equal(message2, message) {
		t.Errorf("decryption failed, got: '%x', want: '%x'", message2, message)
	}
}

func TestEncryptDecryptWithSmallNumbers(t *testing.T) {
	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: big.NewInt(33),
			P: big.NewInt(71),
		},
		X: big.NewInt(42),
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	message := big.NewInt(15).Bytes()
	cypher, err := priv.PublicKey.Encrypt(message, rand.Reader)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}
	message2 := priv.Decrypt(cypher)
	if !bytes.Equal(message2, message) {
		t.Errorf("decryption failed, got: %x, want: %x", message2, message)
	}

}

func TestHomomorphicProperties(t *testing.T) {
	priv := PrivateKey{
		PublicKey: PublicKey{
			G: big.NewInt(33),
			P: big.NewInt(71),
		},
		X: big.NewInt(42),
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	message1 := big.NewInt(11).Bytes()
	cypher1, _ := priv.PublicKey.Encrypt(message1, rand.Reader)

	message2 := big.NewInt(12).Bytes()
	cypher2, _ := priv.PublicKey.Encrypt(message2, rand.Reader)

	decyphered := priv.Decrypt(new(Cypher).Mul(cypher1, cypher2))
	expected := big.NewInt((12 * 11) % 71).Bytes()
	if !bytes.Equal(expected, decyphered) {
		t.Errorf("decryption failed, got: %x, want: %x", decyphered, expected)
	}

}

func TestCypherToJSON(t *testing.T) {
	cypher := &Cypher{
		C1: big.NewInt(33),
		C2: big.NewInt(99),
		P:  big.NewInt(192),
	}
	exp := make(map[string]string)
	exp["C1"] = "21"
	exp["C2"] = "63"
	exp["P"] = "c0"

	if !reflect.DeepEqual(exp, cypher.ToJSON()) {
		t.Error(exp, "is not ", cypher.ToJSON())
	}
}

func TestCypherFromJSON(t *testing.T) {
	m := make(map[string]string)
	m["C1"] = "21"
	m["C2"] = "63"
	m["P"] = "c0"

	cypher, err := new(Cypher).FromJSON(m)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(cypher.P, big.NewInt(192)) {
		t.Error("P not okay")
	}
	if !reflect.DeepEqual(cypher.C1, big.NewInt(33)) {
		t.Error("C1 not okay")
	}
	if !reflect.DeepEqual(cypher.C2, big.NewInt(99)) {
		t.Error("C2 not okay")
	}

}

func TestMarshalling(t *testing.T) {
	cypher := &Cypher{
		C1: big.NewInt(33),
		C2: big.NewInt(99),
		P:  big.NewInt(192),
	}
	s, err := cypher.MarshalJSON()
	if err != nil {
		t.Fail()
	}

	cypher2 := new(Cypher)
	err = cypher2.UnmarshalJSON(s)
	if err != nil {
		t.Error("could not unmarshal", err)
	}

	if !reflect.DeepEqual(cypher, cypher2) {
		t.Error("the two objects do not match!")
	}

}
