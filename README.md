# KG 🇧🇬
KG Bulgarian Trusted Short Weierstrass Elliptic Curves

The KG-256r1 and KG-384r1 curves were proposed by the Bulgarian Academy of Sciences:  
https://arxiv.org/abs/2208.01635

### Exemplo
```go
package main

import (
	"crypto/rand"
	"fmt"

	kg "github.com/pedroalbanese/kg"
)

func main() {
	// Exemplo de uso completo
	fmt.Println("=== KG Crypto Library Demo ===")

	// 1. GERAR PAR DE CHAVES
	privKey, err := kg.GenerateKey(kg.P256r1(), rand.Reader)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Generated private key: %x\n", privKey.D.Bytes())
	fmt.Printf("Public key X: %s\n", privKey.X.String())
	fmt.Printf("Public key Y: %s\n", privKey.Y.String())

	// 2. EXTRAIR CHAVE PÚBLICA
	pubKey := kg.ExtractPublicKey(privKey)
	fmt.Printf("Extracted public key X: %s\n", pubKey.X.String())
	fmt.Printf("Extracted public key Y: %s\n", pubKey.Y.String())

	// 3. CALCULAR CHAVE PÚBLICA A PARTIR DA PRIVADA
	calculatedPub := kg.PublicKeyFromPrivate(privKey)
	fmt.Printf("Calculated public key matches: %t\n",
		calculatedPub.X.Cmp(pubKey.X) == 0 && calculatedPub.Y.Cmp(pubKey.Y) == 0)

	// 4. SERIALIZAÇÃO PKCS#8
	pkcs8Private, err := kg.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("PKCS#8 private key: %d bytes\n", len(pkcs8Private))

	// 5. DESSERIALIZAÇÃO
	parsedPriv, err := kg.ParsePKCS8PrivateKey(pkcs8Private)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parsed private key matches: %t\n", parsedPriv.D.Cmp(privKey.D) == 0)

	// 6. SERIALIZAÇÃO CHAVE PÚBLICA
	pkixPublic, err := kg.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("PKIX public key: %d bytes\n", len(pkixPublic))

	// 7. ECDSA
	message := []byte("Test message")
	signature, err := kg.SignASN1(rand.Reader, privKey, message)
	if err != nil {
		panic(err)
	}

	valid, err := kg.VerifyASN1(pubKey, message, signature)
	fmt.Printf("ECDSA signature valid: %t\n", valid)

	// 8. ECDH
	otherPriv, _ := kg.GenerateKey(kg.P256r1(), rand.Reader)
	secret, err := kg.ECDH(privKey, kg.ExtractPublicKey(otherPriv))
	if err != nil {
		panic(err)
	}
	fmt.Printf("ECDH secret: %x...\n", secret[:16])

	fmt.Println("=== Demo Concluído ===")
}
```

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2025 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
