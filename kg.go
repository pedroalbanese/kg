package kgcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"sync"
)

// OIDs definidos
var (
	oidKG      = asn1.ObjectIdentifier{2, 16, 100, 1, 1, 1}
	oidKG256r1 = asn1.ObjectIdentifier{2, 16, 100, 1, 1, 1, 1}
	oidKG384r1 = asn1.ObjectIdentifier{2, 16, 100, 1, 1, 1, 2}
)

// Estruturas para codificação ASN.1
type ecdsaSignature struct {
	R, S *big.Int
}

// Estruturas para PKCS#8
type privateKeyInfo struct {
	Version             int
	PrivateKeyAlgorithm privateKeyAlgorithm
	PrivateKey          []byte
}

type privateKeyAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type publicKeyInfo struct {
	Algorithm publicKeyAlgorithm
	PublicKey asn1.BitString
}

type publicKeyAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

// KGCurve implementa a interface elliptic.Curve para nossas curvas personalizadas
type KGCurve struct {
	*elliptic.CurveParams
	a *big.Int // coeficiente a
}

// PrivateKey representa uma chave privada KG (compatível com crypto.Signer)
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// PublicKey representa uma chave pública KG (compatível com crypto.PublicKey)
type PublicKey struct {
	Curve *KGCurve
	X, Y  *big.Int
}

// Variáveis globais para as curvas
var (
	kg256r1     *KGCurve
	kg256r1Once sync.Once

	kg384r1     *KGCurve
	kg384r1Once sync.Once
)

// Errors
var (
	ErrInvalidCurve       = errors.New("kgcrypto: invalid curve")
	ErrInvalidPrivateKey  = errors.New("kgcrypto: invalid private key")
	ErrInvalidPublicKey   = errors.New("kgcrypto: invalid public key")
	ErrUnsupportedCurve   = errors.New("kgcrypto: unsupported curve")
	ErrInvalidSignature   = errors.New("kgcrypto: invalid signature")
	ErrSharedKeyIsZero    = errors.New("kgcrypto: shared key is zero")
	ErrInvalidASN1        = errors.New("kgcrypto: invalid ASN.1 encoding")
	ErrPKCS8Encoding      = errors.New("kgcrypto: PKCS#8 encoding error")
	ErrPKCS8Decoding      = errors.New("kgcrypto: PKCS#8 decoding error")
)

// =============================================================================
// IMPLEMENTAÇÃO DA CURVA
// =============================================================================

func (curve *KGCurve) IsOnCurve(x, y *big.Int) bool {
	if x.Sign() == 0 && y.Sign() == 0 {
		return true
	}

	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	ax := new(big.Int).Mul(curve.a, x)

	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, curve.B)
	rhs.Mod(rhs, curve.P)

	return y2.Cmp(rhs) == 0
}

func (curve *KGCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return x2, y2
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return x1, y1
	}
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) == 0 {
			return curve.double(x1, y1)
		}
		return new(big.Int), new(big.Int)
	}

	y2MinusY1 := new(big.Int).Sub(y2, y1)
	x2MinusX1 := new(big.Int).Sub(x2, x1)
	x2MinusX1Inv := new(big.Int).ModInverse(x2MinusX1, curve.P)
	lambda := new(big.Int).Mul(y2MinusY1, x2MinusX1Inv)
	lambda.Mod(lambda, curve.P)

	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, curve.P)

	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y1)
	y3.Mod(y3, curve.P)

	return x3, y3
}

func (curve *KGCurve) double(x, y *big.Int) (*big.Int, *big.Int) {
	x2 := new(big.Int).Mul(x, x)
	threeX2 := new(big.Int).Mul(big.NewInt(3), x2)
	numerator := new(big.Int).Add(threeX2, curve.a)

	twoY := new(big.Int).Mul(big.NewInt(2), y)
	denomInv := new(big.Int).ModInverse(twoY, curve.P)

	lambda := new(big.Int).Mul(numerator, denomInv)
	lambda.Mod(lambda, curve.P)

	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), x))
	x3.Mod(x3, curve.P)

	y3 := new(big.Int).Sub(x, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y)
	y3.Mod(y3, curve.P)

	return x3, y3
}

func (curve *KGCurve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	kInt := new(big.Int).SetBytes(k)
	resultX := new(big.Int)
	resultY := new(big.Int)
	tempX := new(big.Int).Set(x1)
	tempY := new(big.Int).Set(y1)

	for i := 0; i < kInt.BitLen(); i++ {
		if kInt.Bit(i) == 1 {
			if resultX.Sign() == 0 && resultY.Sign() == 0 {
				resultX.Set(tempX)
				resultY.Set(tempY)
			} else {
				resultX, resultY = curve.Add(resultX, resultY, tempX, tempY)
			}
		}
		tempX, tempY = curve.double(tempX, tempY)
	}

	return resultX, resultY
}

func (curve *KGCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

// Params retorna os parâmetros da curva
func (curve *KGCurve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// =============================================================================
// INICIALIZAÇÃO DAS CURVAS
// =============================================================================

func initKG256r1() {
	params := &elliptic.CurveParams{
		Name:    "KG256r1",
		BitSize: 256,
	}

	params.P, _ = new(big.Int).SetString("105659876450476807015340827963890761976980048986351025435035631207814085532543", 10)
	params.B, _ = new(big.Int).SetString("102451950841073747949316796495896937960702115486975363798323596797327090813462", 10)
	params.N, _ = new(big.Int).SetString("105659876450476807015340827963890761976544313325663770762399235394744121359871", 10)
	params.Gx, _ = new(big.Int).SetString("5385166333114646497810998074612415985821986371151485954586014078688791960064", 10)
	params.Gy, _ = new(big.Int).SetString("88440166531789946723126083546750633179866039092883764784041611065547926159080", 10)

	a, _ := new(big.Int).SetString("57780130698115176583488499171344771088898507337873238590400955371129685138826", 10)

	kg256r1 = &KGCurve{
		CurveParams: params,
		a:           a,
	}
}

func initKG384r1() {
	params := &elliptic.CurveParams{
		Name:    "KG384r1",
		BitSize: 384,
	}

	params.P, _ = new(big.Int).SetString("30850493656680149340079966421756113888797201705900966381840288086888802411176587972020735012523469267564505420764051", 10)
	params.B, _ = new(big.Int).SetString("2826799144410810451940649796749865660531410575292534383976745724330749097582395451638354661270280127278365677483939", 10)
	params.N, _ = new(big.Int).SetString("30850493656680149340079966421756113888797201705900966381841438754683900390077617323565554872996073979103765917522731", 10)
	params.Gx, _ = new(big.Int).SetString("26382167469722729078686791539259191084630652622205406190302146794523414127451183423914120811487055055064792875345576", 10)
	params.Gy, _ = new(big.Int).SetString("20262805131660615219589586646228078501545181834199642151194102089344927295889857293563989127020260020122002404045204", 10)

	a, _ := new(big.Int).SetString("2689376848857934359417998845213258254140716666751951067196901653139051892648485257788827989185822359193013251735562", 10)

	kg384r1 = &KGCurve{
		CurveParams: params,
		a:           a,
	}
}

// =============================================================================
// FUNÇÕES PÚBLICAS DA CURVA
// =============================================================================

// P256r1 retorna a curva KG256r1
func P256r1() *KGCurve {
	kg256r1Once.Do(initKG256r1)
	return kg256r1
}

// P384r1 retorna a curva KG384r1
func P384r1() *KGCurve {
	kg384r1Once.Do(initKG384r1)
	return kg384r1
}

// GetCurveByName retorna uma curva pelo nome
func GetCurveByName(name string) (*KGCurve, error) {
	switch name {
	case "KG256r1", "P256r1":
		return P256r1(), nil
	case "KG384r1", "P384r1":
		return P384r1(), nil
	default:
		return nil, ErrUnsupportedCurve
	}
}

// =============================================================================
// IMPLEMENTAÇÃO DAS CHAVES
// =============================================================================

// Equal compara duas chaves públicas
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.X.Cmp(xx.X) == 0 && pub.Y.Cmp(xx.Y) == 0 && pub.Curve == xx.Curve
}

// Public retorna a chave pública (implementa crypto.Signer)
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// ExtractPublicKey extrai a chave pública de uma chave privada
func ExtractPublicKey(priv *PrivateKey) *PublicKey {
	if priv == nil || priv.D == nil {
		return nil
	}
	return &PublicKey{
		Curve: priv.Curve,
		X:     priv.X,
		Y:     priv.Y,
	}
}

// PublicKeyFromPrivate calcula a chave pública a partir de uma chave privada
// Útil quando você só tem a chave privada e precisa gerar a pública
func PublicKeyFromPrivate(priv *PrivateKey) *PublicKey {
	if priv == nil || priv.D == nil {
		return nil
	}
	
	// Se já temos as coordenadas X e Y, retornar diretamente
	if priv.X != nil && priv.Y != nil {
		return &PublicKey{
			Curve: priv.Curve,
			X:     priv.X,
			Y:     priv.Y,
		}
	}
	
	// Calcular a chave pública: Q = d * G
	x, y := priv.Curve.ScalarBaseMult(priv.D.Bytes())
	return &PublicKey{
		Curve: priv.Curve,
		X:     x,
		Y:     y,
	}
}

// =============================================================================
// SERIALIZAÇÃO PKCS#8
// =============================================================================

// MarshalPKCS8PrivateKey serializa uma chave privada para formato PKCS#8
func MarshalPKCS8PrivateKey(priv *PrivateKey) ([]byte, error) {
	if priv == nil || priv.D == nil {
		return nil, ErrInvalidPrivateKey
	}

	// Obter OID da curva
	var curveOID asn1.ObjectIdentifier
	switch priv.Curve.Params().Name {
	case "KG256r1":
		curveOID = oidKG256r1
	case "KG384r1":
		curveOID = oidKG384r1
	default:
		return nil, ErrUnsupportedCurve
	}

	// Codificar chave privada EC
	privateKeyBytes := priv.D.Bytes()
	N := priv.Curve.Params().N
	byteSize := (N.BitLen() + 7) / 8

	// Preencher com zeros à esquerda se necessário
	if len(privateKeyBytes) < byteSize {
		padded := make([]byte, byteSize)
		copy(padded[byteSize-len(privateKeyBytes):], privateKeyBytes)
		privateKeyBytes = padded
	}

	// Codificar chave pública
	pubBytes := elliptic.Marshal(priv.Curve, priv.X, priv.Y)

	ecPrivateKey := ecPrivateKey{
		Version:       1,
		PrivateKey:    privateKeyBytes,
		NamedCurveOID: curveOID,
		PublicKey:     asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
	}

	ecPrivateKeyBytes, err := asn1.Marshal(ecPrivateKey)
	if err != nil {
		return nil, ErrPKCS8Encoding
	}

	// Codificar parâmetros da curva
	paramBytes, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, ErrPKCS8Encoding
	}

	privateKeyInfo := privateKeyInfo{
		Version: 0,
		PrivateKeyAlgorithm: privateKeyAlgorithm{
			Algorithm: oidKG,
			Parameters: asn1.RawValue{
				FullBytes: paramBytes,
			},
		},
		PrivateKey: ecPrivateKeyBytes,
	}

	return asn1.Marshal(privateKeyInfo)
}

// ParsePKCS8PrivateKey analisa uma chave privada no formato PKCS#8
func ParsePKCS8PrivateKey(der []byte) (*PrivateKey, error) {
	var pki privateKeyInfo
	if _, err := asn1.Unmarshal(der, &pki); err != nil {
		return nil, ErrPKCS8Decoding
	}

	if !pki.PrivateKeyAlgorithm.Algorithm.Equal(oidKG) {
		return nil, ErrUnsupportedCurve
	}

	// Extrair OID da curva dos parâmetros
	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(pki.PrivateKeyAlgorithm.Parameters.FullBytes, &curveOID); err != nil {
		return nil, ErrPKCS8Decoding
	}

	// Determinar a curva baseado no OID
	var curve *KGCurve
	switch {
	case curveOID.Equal(oidKG256r1):
		curve = P256r1()
	case curveOID.Equal(oidKG384r1):
		curve = P384r1()
	default:
		return nil, ErrUnsupportedCurve
	}

	// Decodificar chave privada EC
	var ecPriv ecPrivateKey
	if _, err := asn1.Unmarshal(pki.PrivateKey, &ecPriv); err != nil {
		return nil, ErrPKCS8Decoding
	}

	if ecPriv.Version != 1 {
		return nil, ErrPKCS8Decoding
	}

	// Extrair chave privada
	k := new(big.Int).SetBytes(ecPriv.PrivateKey)

	// Extrair chave pública se disponível
	var x, y *big.Int
	if len(ecPriv.PublicKey.Bytes) > 0 {
		x, y = elliptic.Unmarshal(curve, ecPriv.PublicKey.Bytes)
		if x == nil {
			// Se não conseguir decodificar a chave pública, calcular a partir da privada
			x, y = curve.ScalarBaseMult(k.Bytes())
		}
	} else {
		// Calcular chave pública a partir da privada
		x, y = curve.ScalarBaseMult(k.Bytes())
	}

	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: k,
	}, nil
}

// MarshalPKIXPublicKey serializa uma chave pública para formato PKIX
func MarshalPKIXPublicKey(pub *PublicKey) ([]byte, error) {
	if pub == nil || pub.Curve == nil {
		return nil, ErrInvalidPublicKey
	}

	// Obter OID da curva
	var curveOID asn1.ObjectIdentifier
	switch pub.Curve.Params().Name {
	case "KG256r1":
		curveOID = oidKG256r1
	case "KG384r1":
		curveOID = oidKG384r1
	default:
		return nil, ErrUnsupportedCurve
	}

	// Codificar chave pública
	pubBytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)

	// Codificar parâmetros da curva
	paramBytes, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, ErrPKCS8Encoding
	}

	publicKeyInfo := publicKeyInfo{
		Algorithm: publicKeyAlgorithm{
			Algorithm: oidKG,
			Parameters: asn1.RawValue{
				FullBytes: paramBytes,
			},
		},
		PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
	}

	return asn1.Marshal(publicKeyInfo)
}

// ParsePKIXPublicKey analisa uma chave pública no formato PKIX
func ParsePKIXPublicKey(der []byte) (*PublicKey, error) {
	var pki publicKeyInfo
	if _, err := asn1.Unmarshal(der, &pki); err != nil {
		return nil, ErrPKCS8Decoding
	}

	if !pki.Algorithm.Algorithm.Equal(oidKG) {
		return nil, ErrUnsupportedCurve
	}

	// Extrair OID da curva dos parâmetros
	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(pki.Algorithm.Parameters.FullBytes, &curveOID); err != nil {
		return nil, ErrPKCS8Decoding
	}

	// Determinar a curva baseado no OID
	var curve *KGCurve
	switch {
	case curveOID.Equal(oidKG256r1):
		curve = P256r1()
	case curveOID.Equal(oidKG384r1):
		curve = P384r1()
	default:
		return nil, ErrUnsupportedCurve
	}

	// Decodificar chave pública
	x, y := elliptic.Unmarshal(curve, pki.PublicKey.Bytes)
	if x == nil {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// =============================================================================
// FUNÇÕES ECDSA
// =============================================================================

// GenerateKey gera um par de chaves para a curva especificada
func GenerateKey(curve *KGCurve, rand io.Reader) (*PrivateKey, error) {
	if curve == nil {
		return nil, ErrInvalidCurve
	}

	N := curve.Params().N
	bitSize := N.BitLen()
	byteSize := (bitSize + 7) / 8

	for {
		bytes := make([]byte, byteSize)
		if _, err := io.ReadFull(rand, bytes); err != nil {
			return nil, err
		}

		// Limpar bits extras para garantir k < N
		if excess := len(bytes)*8 - bitSize; excess > 0 {
			bytes[0] >>= excess
			bytes[0] <<= excess
		}

		k := new(big.Int).SetBytes(bytes)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			return newPrivateKey(curve, k), nil
		}
	}
}

// newPrivateKey cria uma nova chave privada
func newPrivateKey(curve *KGCurve, d *big.Int) *PrivateKey {
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}
}

// Sign assina uma mensagem (implementa crypto.Signer)
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return SignASN1(rand, priv, digest)
}

// Verify verifica uma assinatura
func (pub *PublicKey) Verify(digest, signature []byte) bool {
	_, err := VerifyASN1(pub, digest, signature)
	return err == nil
}

// SignASN1 assina uma mensagem e retorna a assinatura codificada em ASN.1
func SignASN1(rand io.Reader, priv *PrivateKey, digest []byte) ([]byte, error) {
	if priv.D == nil {
		return nil, ErrInvalidPrivateKey
	}

	curve := priv.Curve
	N := curve.Params().N

	// Hash da mensagem
	hash := hashMessage(digest, (N.BitLen()+7)/8)
	hashInt := new(big.Int).SetBytes(hash)
	hashInt.Mod(hashInt, N)

	var r, s *big.Int
	var k *big.Int
	var err error

	for {
		// Gerar k aleatório
		k, err = randFieldElement(curve, rand)
		if err != nil {
			return nil, err
		}

		// Calcular r = (k * G).x mod N
		rX, _ := curve.ScalarBaseMult(k.Bytes())
		r = new(big.Int).Mod(rX, N)

		if r.Sign() == 0 {
			continue
		}

		// Calcular s = k⁻¹ * (hash + r * privKey) mod N
		kInv := new(big.Int).ModInverse(k, N)
		rTimesPriv := new(big.Int).Mul(r, priv.D)
		rTimesPriv.Mod(rTimesPriv, N)

		hashPlusRPriv := new(big.Int).Add(hashInt, rTimesPriv)
		hashPlusRPriv.Mod(hashPlusRPriv, N)

		s = new(big.Int).Mul(kInv, hashPlusRPriv)
		s.Mod(s, N)

		if s.Sign() != 0 {
			break
		}
	}

	// Codificar em ASN.1
	signature := ecdsaSignature{R: r, S: s}
	return asn1.Marshal(signature)
}

// VerifyASN1 verifica uma assinatura codificada em ASN.1
func VerifyASN1(pub *PublicKey, digest, signature []byte) (bool, error) {
	if pub.Curve == nil {
		return false, ErrInvalidPublicKey
	}

	// Decodificar assinatura ASN.1
	var asn1Sig ecdsaSignature
	rest, err := asn1.Unmarshal(signature, &asn1Sig)
	if err != nil {
		return false, ErrInvalidASN1
	}
	if len(rest) != 0 {
		return false, ErrInvalidASN1
	}

	r, s := asn1Sig.R, asn1Sig.S

	curve := pub.Curve
	N := curve.Params().N

	// Verificar limites
	if r.Sign() <= 0 || r.Cmp(N) >= 0 {
		return false, ErrInvalidSignature
	}
	if s.Sign() <= 0 || s.Cmp(N) >= 0 {
		return false, ErrInvalidSignature
	}

	// Verificar se a chave pública está na curva
	if !curve.IsOnCurve(pub.X, pub.Y) {
		return false, ErrInvalidPublicKey
	}

	// Hash da mensagem
	hash := hashMessage(digest, (N.BitLen()+7)/8)
	hashInt := new(big.Int).SetBytes(hash)
	hashInt.Mod(hashInt, N)

	// Calcular w = s⁻¹ mod N
	w := new(big.Int).ModInverse(s, N)
	if w == nil {
		return false, ErrInvalidSignature
	}

	// Calcular u1 = hash * w mod N
	u1 := new(big.Int).Mul(hashInt, w)
	u1.Mod(u1, N)

	// Calcular u2 = r * w mod N
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, N)

	// Calcular ponto = u1 * G + u2 * Q
	x1, y1 := curve.ScalarBaseMult(u1.Bytes())
	x2, y2 := curve.ScalarMult(pub.X, pub.Y, u2.Bytes())
	x, y := curve.Add(x1, y1, x2, y2)

	if x.Sign() == 0 && y.Sign() == 0 {
		return false, ErrInvalidSignature
	}

	// Verificar se r ≡ x mod N
	valid := x.Mod(x, N).Cmp(r) == 0
	if !valid {
		return false, ErrInvalidSignature
	}

	return true, nil
}

// =============================================================================
// FUNÇÃO ECDH
// =============================================================================

// ECDH calcula o segredo compartilhado usando Diffie-Hellman de curva elíptica
func ECDH(priv *PrivateKey, pub *PublicKey) ([]byte, error) {
	if priv == nil || priv.D == nil {
		return nil, ErrInvalidPrivateKey
	}
	if pub == nil {
		return nil, ErrInvalidPublicKey
	}
	if priv.Curve != pub.Curve {
		return nil, errors.New("kgcrypto: curves mismatch")
	}
	if !priv.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, ErrInvalidPublicKey
	}

	// Calcular ponto compartilhado
	sharedX, sharedY := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())

	if sharedX.Sign() == 0 && sharedY.Sign() == 0 {
		return nil, ErrSharedKeyIsZero
	}

	// O segredo compartilhado é a coordenada x
	byteSize := (priv.Curve.Params().BitSize + 7) / 8
	sharedSecret := make([]byte, byteSize)
	sharedXBytes := sharedX.Bytes()
	copy(sharedSecret[byteSize-len(sharedXBytes):], sharedXBytes)

	return sharedSecret, nil
}

// =============================================================================
// FUNÇÕES AUXILIARES
// =============================================================================

// randFieldElement retorna um elemento aleatório do campo
func randFieldElement(curve *KGCurve, rand io.Reader) (k *big.Int, err error) {
	N := curve.Params().N
	bitSize := N.BitLen()
	byteSize := (bitSize + 7) / 8

	for {
		bytes := make([]byte, byteSize)
		if _, err = io.ReadFull(rand, bytes); err != nil {
			return nil, err
		}

		// Limpar bits extras para garantir k < N
		if excess := len(bytes)*8 - bitSize; excess > 0 {
			bytes[0] >>= excess
			bytes[0] <<= excess
		}

		k = new(big.Int).SetBytes(bytes)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			return
		}
	}
}

// hashMessage calcula o hash de uma mensagem
func hashMessage(message []byte, size int) []byte {
	hash := new(big.Int)
	for _, b := range message {
		hash.Lsh(hash, 8)
		hash.Add(hash, big.NewInt(int64(b)))
	}

	hashBytes := hash.Bytes()
	if len(hashBytes) > size {
		hashBytes = hashBytes[:size]
	}

	result := make([]byte, size)
	copy(result[size-len(hashBytes):], hashBytes)
	return result
}

// =============================================================================
// FUNÇÕES DE CONVERSÃO (para compatibilidade com crypto/ecdsa)
// =============================================================================

// FromECDSA converte uma chave ecdsa.PrivateKey para PrivateKey
func FromECDSA(ecdsaPriv *ecdsa.PrivateKey) (*PrivateKey, error) {
	if ecdsaPriv == nil {
		return nil, ErrInvalidPrivateKey
	}

	// Determinar qual curva KG corresponde
	var curve *KGCurve
	switch ecdsaPriv.Curve.Params().Name {
	case "KG256r1":
		curve = P256r1()
	case "KG384r1":
		curve = P384r1()
	default:
		return nil, ErrUnsupportedCurve
	}

	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: curve,
			X:     ecdsaPriv.X,
			Y:     ecdsaPriv.Y,
		},
		D: ecdsaPriv.D,
	}, nil
}

// ToECDSA converte uma PrivateKey para ecdsa.PrivateKey
func (priv *PrivateKey) ToECDSA() (*ecdsa.PrivateKey, error) {
	if priv.D == nil {
		return nil, ErrInvalidPrivateKey
	}

	// Converter curva KG para curva elliptic
	var curve elliptic.Curve
	switch priv.Curve.Params().Name {
	case "KG256r1":
		curve = P256r1()
	case "KG384r1":
		curve = P384r1()
	default:
		return nil, ErrUnsupportedCurve
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     priv.X,
			Y:     priv.Y,
		},
		D: priv.D,
	}, nil
}

// =============================================================================
// EXEMPLO DE USO (função main para demonstração)
// =============================================================================

/*
func main() {
	// Exemplo de uso completo
	fmt.Println("=== KG Crypto Library Demo ===")
	
	// 1. GERAR PAR DE CHAVES
	privKey, err := GenerateKey(P256r1(), rand.Reader)
	if err != nil {
		panic(err)
	}
	
	fmt.Printf("Generated private key: %x\n", privKey.D.Bytes())
	fmt.Printf("Public key X: %s\n", privKey.X.String())
	fmt.Printf("Public key Y: %s\n", privKey.Y.String())
	
	// 2. EXTRAIR CHAVE PÚBLICA
	pubKey := ExtractPublicKey(privKey)
	fmt.Printf("Extracted public key X: %s\n", pubKey.X.String())
	fmt.Printf("Extracted public key Y: %s\n", pubKey.Y.String())
	
	// 3. CALCULAR CHAVE PÚBLICA A PARTIR DA PRIVADA
	calculatedPub := PublicKeyFromPrivate(privKey)
	fmt.Printf("Calculated public key matches: %t\n", 
		calculatedPub.X.Cmp(pubKey.X) == 0 && calculatedPub.Y.Cmp(pubKey.Y) == 0)
	
	// 4. SERIALIZAÇÃO PKCS#8
	pkcs8Private, err := MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("PKCS#8 private key: %d bytes\n", len(pkcs8Private))
	
	// 5. DESSERIALIZAÇÃO
	parsedPriv, err := ParsePKCS8PrivateKey(pkcs8Private)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parsed private key matches: %t\n", parsedPriv.D.Cmp(privKey.D) == 0)
	
	// 6. SERIALIZAÇÃO CHAVE PÚBLICA
	pkixPublic, err := MarshalPKIXPublicKey(pubKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("PKIX public key: %d bytes\n", len(pkixPublic))
	
	// 7. ECDSA
	message := []byte("Test message")
	signature, err := SignASN1(rand.Reader, privKey, message)
	if err != nil {
		panic(err)
	}
	
	valid, err := VerifyASN1(pubKey, message, signature)
	fmt.Printf("ECDSA signature valid: %t\n", valid)
	
	// 8. ECDH
	otherPriv, _ := GenerateKey(P256r1(), rand.Reader)
	secret, err := ECDH(privKey, ExtractPublicKey(otherPriv))
	if err != nil {
		panic(err)
	}
	fmt.Printf("ECDH secret: %x...\n", secret[:16])
}
*/
