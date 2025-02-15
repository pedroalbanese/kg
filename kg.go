package kg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
	"sync"
	"errors"
)

// oid 2.16.100.1.1.1

var (
	oidKG = asn1.ObjectIdentifier{2, 16, 100, 1, 1, 1}

	oidKG256r1 = asn1.ObjectIdentifier{2, 16, 100, 1, 1, 1, 1}
	oidKG384r1 = asn1.ObjectIdentifier{2, 16, 100, 1, 1, 1, 2}
)

// Changing the type of `kg` to *rcurve, since `newRcurve` returns this type.
var kg256, kg384 *rcurve

// sync.Once variable to ensure initialization occurs only once
var initonce sync.Once

// Initialization of curve P256
func init() {
	initP256()
	initP384()
}

// Function to initialize curve P256
func initP256() {
	// Initializing the P256 curve directly without calling P256 inside it
	twisted := elliptic.P256().Params()

	// Defining curve parameters for kg256r1
	params := &elliptic.CurveParams{
		Name:    "kg256r1",
		P:       new(big.Int).Set(twisted.P),
		N:       new(big.Int).Set(twisted.N),
		BitSize: twisted.BitSize,
	}

	// Defining the coordinates Gx and Gy
	params.Gx, _ = new(big.Int).SetString("BE7E568DA4666BF6DC2702E5D1E33BB30C3D65EDC5EA96820412D0894811A00", 16)
	params.Gy, _ = new(big.Int).SetString("C3875C40ACE3CE0F5E42DF37A60BACA589D09A795B9CF2F64727BB3623A23EE8", 16)
	r, _ := new(big.Int).SetString("E9995EEC1C1CE7099201839743B93D30FE6E8748C087317013C8F358B074FDFF", 16)

	// Initializing the global `kg` variable with the generated curve
	kg256 = newRcurve(elliptic.P256(), params, r)
}

// Function to return the P256 curve, using the initialization done in init
func P256() elliptic.Curve {
	initonce.Do(initP256) // This ensures that `initP256` will be called only once
	return kg256
}

// Function to initialize curve P384
func initP384() {
	// Initializing the P384 curve directly without calling P384 inside it
	twisted := elliptic.P384().Params()

	// Defining curve parameters for kg384r1
	params := &elliptic.CurveParams{
		Name:    "kg384r1",
		P:       new(big.Int).Set(twisted.P),
		N:       new(big.Int).Set(twisted.N),
		BitSize: twisted.BitSize,
	}

	// Defining the coordinates Gx and Gy
	params.Gx, _ = new(big.Int).SetString("AB688CF535527F21551631672D29703A59D132A47E6FEEBB2FD21E55898110859CA579D7AAED2AA7AB12964EEED326A8", 16)
	params.Gy, _ = new(big.Int).SetString("83A66D0CB601A1AC39FF57035C141C78F75CD4214C56A82C9BE1573FA1D0B1CA8988D4F61AB9C14F70D61BA212867194", 16)
	r, _ := new(big.Int).SetString("C870904DAF5C19DCC5D126956C3749F7A56A76713ABF601D38AB335003AD237D1CFDE925869B93E9B69D63A89FC6DB2B", 16)

	// Initializing the global `kg` variable with the generated curve
	kg384 = newRcurve(elliptic.P384(), params, r)
}

// Function to return the P384 curve, using the initialization done in init
func P384() elliptic.Curve {
	initonce.Do(initP384) // This ensures that `initP384` will be called only once
	return kg384
}

// Structures to represent public and private keys
type PublicKey struct {
	X, Y  *big.Int
	Curve elliptic.Curve
}

type PrivateKey struct {
	PublicKey PublicKey
	D         *big.Int
}

// Function to convert the public key to ECDSA
func (pk *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: pk.Curve,
		X:     pk.X,
		Y:     pk.Y,
	}
}

// Function to convert the private key to ECDSA
func (pk *PrivateKey) ToECDSAPrivateKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: pk.PublicKey.Curve,
			X:     pk.PublicKey.X,
			Y:     pk.PublicKey.Y,
		},
		D: pk.D,
	}
}

// Function to create a new private key from an ECDSA private key
func NewPrivateKey(privateKey *ecdsa.PrivateKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: privateKey.PublicKey.Curve,
			X:     privateKey.PublicKey.X,
			Y:     privateKey.PublicKey.Y,
		},
		D: privateKey.D,
	}
}

func ECDH(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Compute shared key
	x, _ := privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	return x.Bytes(), nil
}

// Define pkAlgorithmIdentifier to avoid undefined identifier
type pkAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

func (pk *PublicKey) MarshalPKCS8PublicKey(curve elliptic.Curve) ([]byte, error) {
	// Marshal the public key coordinates
	derBytes := elliptic.Marshal(curve, pk.X, pk.Y)

	// Determine the OID based on the curve
	var oid asn1.ObjectIdentifier
	switch curve {
	case P256():
		oid = oidKG256r1
	case P384():
		oid = oidKG384r1
	default:
		return nil, errors.New("unsupported curve")
	}

	// Create a SubjectPublicKeyInfo structure
	subjectPublicKeyInfo := struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkAlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: asn1.TagOID, Bytes: []byte(oid.String())},
		},
		PublicKey: asn1.BitString{Bytes: derBytes, BitLength: len(derBytes) * 8},
	}

	// Marshal the SubjectPublicKeyInfo structure
	derBytes, err := asn1.Marshal(subjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}

func ParsePublicKey(der []byte) (*PublicKey, error) {
	var publicKeyInfo struct {
		Algorithm pkAlgorithmIdentifier
		PublicKey asn1.BitString
	}

	_, err := asn1.Unmarshal(der, &publicKeyInfo)
	if err != nil {
		return nil, err
	}

	var curve elliptic.Curve
	switch {
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidKG256r1):
		curve = P256()
	case publicKeyInfo.Algorithm.Algorithm.Equal(oidKG384r1):
		curve = P384()
	default:
		return nil, errors.New("unsupported curve OID")
	}

	// Check if the public key bytes are empty
	if len(publicKeyInfo.PublicKey.Bytes) == 0 {
		return nil, errors.New("public key bytes are empty")
	}

	// Unmarshal the public key coordinates
	X, Y := elliptic.Unmarshal(curve, publicKeyInfo.PublicKey.Bytes)
	if X == nil || Y == nil {
		return nil, errors.New("failed to unmarshal public key")
	}

	// Return the parsed public key with the determined curve
	return &PublicKey{X: X, Y: Y, Curve: curve}, nil
}

func (pk *PrivateKey) MarshalPKCS8PrivateKey(curve elliptic.Curve) ([]byte, error) {
	if !curve.IsOnCurve(pk.PublicKey.X, pk.PublicKey.Y) {
		return nil, errors.New("Public key is not on the curve")
	}

	// Convert the private key D to bytes
	dBytes := pk.D.Bytes()

	curveSize := (curve.Params().BitSize + 7) / 8
	if len(dBytes) < curveSize {
		padding := make([]byte, curveSize-len(dBytes))
		dBytes = append(padding, dBytes...)
	}

	// Determine the OID based on the curve
	var oid asn1.ObjectIdentifier
	switch curve {
	case P256():
		oid = oidKG256r1
	case P384():
		oid = oidKG384r1
	default:
		return nil, errors.New("unsupported curve")
	}

	// Create a PrivateKeyInfo structure
	privateKeyInfo := struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PublicKey           struct {
			X *big.Int
			Y *big.Int
		}
		PrivateKey []byte
	}{
		Version: 0,
		PrivateKeyAlgorithm: pkAlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: asn1.TagOID, Bytes: []byte(oid.String())},
		},
		PublicKey: struct {
			X *big.Int
			Y *big.Int
		}{
			X: new(big.Int).SetBytes(pk.PublicKey.X.Bytes()),
			Y: new(big.Int).SetBytes(pk.PublicKey.Y.Bytes()),
		},
		PrivateKey: dBytes,
	}

	// Marshal the PrivateKeyInfo structure
	derBytes, err := asn1.Marshal(privateKeyInfo)
	if err != nil {
		return nil, err
	}

	return derBytes, nil
}

func ParsePrivateKey(der []byte) (*PrivateKey, error) {
	var privateKeyInfo struct {
		Version             int
		PrivateKeyAlgorithm pkAlgorithmIdentifier
		PublicKey           struct {
			X *big.Int
			Y *big.Int
		}
		PrivateKey []byte
	}
	_, err := asn1.Unmarshal(der, &privateKeyInfo)
	if err != nil {
		return nil, err
	}

	// Determine the curve based on the OID
	var curve elliptic.Curve
	switch {
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidKG256r1):
		curve = P256()
	case privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Equal(oidKG384r1):
		curve = P384()
	default:
		return nil, errors.New("unsupported curve OID")
	}

	X := privateKeyInfo.PublicKey.X
	Y := privateKeyInfo.PublicKey.Y
	D := new(big.Int).SetBytes(privateKeyInfo.PrivateKey)

	if !curve.IsOnCurve(X, Y) {
		return nil, errors.New("Public key is not on the curve")
	}

	// Create and return the private key with the determined curve
	privateKey := &PrivateKey{
		PublicKey: PublicKey{
			X:     X,
			Y:     Y,
			Curve: curve,
		},
		D: D,
	}

	return privateKey, nil
}
