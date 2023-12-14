package nestedtoken

// This package contains the main structs and functions to implement the nested token model as specified in 
// https://docs.google.com/document/d/1nQYV4wf8wiogpxboIVbwtFZyZjLNRejyguHoGZIZLQM

import (
	"fmt"
	"encoding/base64"
	"encoding/json"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/ecdsa"
	"log"
	"github.com/hpe-usp-spire/schoco"
	"go.dedis.ch/kyber/v3"
)

// The token must contain a Payload and a Signature. 
// The Nested value is optional, and must be used when extending the token.
type Token struct {	
	Nested		*Token					`json:"nested,omitempty"`
	Payload		*Payload				`json:"payload"`
	Signature	[]byte					`json:"signature"`
}

// The mandatory claims are pre-defined. Any other info to be added must be inserted into Data.
type Payload struct {
	Ver 		int8					`json:"ver,omitempty"`
	Iat			int64					`json:"iat,omitempty"`
	Iss			*IDClaim				`json:"iss,omitempty"`
	Aud			*IDClaim				`json:"aud,omitempty"`
	Sub			*IDClaim				`json:"sub,omitempty"`
	Data		map[string]interface{}	`json:"data,omitempty"`
}

// Claim designed to carry specific identity informations
type IDClaim struct {
	CN			string					`json:"cn,omitempty"` // e.g.: spiffe://example.org/workload
	PK			[]byte					`json:"pk,omitempty"` // e.g.: VGhpcyBpcyBteSBQdWJsaWMgS2V5
	ID			*Token					`json:"id,omitempty"` // e.g.: a complete ID
}

// Token -> string
func Encode(token *Token) (string, error) {
	// Marshal the Token struct into JSON
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("error marshaling Token to JSON: %v\n", err)
	}

	// Encode the JSON byte slice to Base64.RawURLEncoded string
	encToken := base64.RawURLEncoding.EncodeToString(tokenJSON)

	return encToken, nil
}

// string -> Token
func Decode(encToken string) (*Token, error) {

    // Decode the base64.RawURLEncoded Token
    decoded, err := base64.RawURLEncoding.DecodeString(encToken)
    if err != nil {
        return nil, fmt.Errorf("error decoding Token: %v\n", err)
    }
	// log.Printf("Decoded Token to be unmarshaled: %s\n", decoded)

    // Unmarshal the decoded byte slice into your struct
    var decToken Token
    err = json.Unmarshal(decoded, &decToken)
    if err != nil {
        return nil, fmt.Errorf("error unmarshalling Token: %v\n", err)
    }
	// log.Printf("Return value: %v\n", decToken)
    return &decToken, nil
}

// Create a new Token (a.k.a. sign)
// If key not informed, uses randomkey and Anon mode EDDSA
// otherwise, use ID-mode with ECDSA
// Version follows specification document, where 0 = ID mode with ECDSA and 1 = SchoCo
func Create(newPayload *Payload, version int8, key interface{}) (*Token, error) {

	newToken := &Token{
		Payload:	newPayload,	
	}

	// Marshal to JSON
	tmpToSign, err := json.Marshal(newToken)
	if err != nil {
		return nil, fmt.Errorf("Error generating json: %v\n", err)
	} 

	// Choose between ID / SchoCo
	var s []byte
    switch version {
	case 0:
		// Create new token usin ID mode with ECDSA
		// Sign Token
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an ECDSA private key")
		}

		hash 	:= sha256.Sum256(tmpToSign)
		s, err = ecdsaKey.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("Error generating signed assertion: %v\n", err)
		} 

	case 1:
		// Create new token using schnorr concatenation (SchoCo) with EdDSA25519
		eddsaKey, ok := key.(kyber.Scalar)
		if !ok {
			return nil, fmt.Errorf("key is not an EdDSA private key")
		}

		// Sign with new key
		sig := schoco.StdSign(fmt.Sprintf("%s", tmpToSign), eddsaKey)
		s, err = sig.ToByte()
		if err != nil {
			return nil, fmt.Errorf("Error generating signed assertion: %v\n", err)
		} 
	}

	// Set Token signature
	newToken.Signature = s

	// // Encode signed Token
	// outToken, err := Encode(newToken)
	// if err != nil {
	// 	return "", fmt.Errorf("Error encoding Token: %v\n", err)
	// } 

	return newToken, nil
}

// Extend an existing token with a new payload, and sign using provided key
// If key not informed, uses anon mode validation (SchoCo)
// otherwise, use ID-mode with ECDSA
func Extend(token *Token, newPayload *Payload, version int8, key ...interface{}) (*Token, error) {
	// TODO: Modify the payload struct to support custom claims (maybe using map[string]{interface})
	// Create the extended Token structure
	
	// Choose between ID / SchoCo
	var s []byte
	var newToken *Token
	// var outToken string
    switch version {
	case 0:
		// Uses ECDSA
		// TODO generalize
		// Sign Token

		// Define the new struct
		newToken = &Token{
			Nested:		token,
			Payload:	newPayload,	
		}

		// Marshal to JSON
		tmpToSign, err := json.Marshal(newToken)
		if err != nil {
			return nil, fmt.Errorf("Error generating json: %v\n", err)
		} 

		ecdsaKey, ok := key[0].(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an ECDSA private key")
		}
			
		hash 	:= sha256.Sum256(tmpToSign)
		s, err = ecdsaKey.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("Error generating signed assertion: %v\n", err)
		} 

		// Set extToken signature
		newToken.Signature = s

		// // Encode signed Token
		// outToken, err = Encode(newToken)
		// if err != nil {
		// 	return nil, fmt.Errorf("Error encoding Token: %v\n", err)
		// } 

	case 1:
		// Uses schoco

		// Convert []byte to sig
		sig, err := schoco.ByteToSignature(token.Signature)

		// extract key from signature
		aggKey, partSig := sig.ExtractAggKey()

		// convert partsig to byte
		partSigBytes, err := schoco.PointToByte(partSig)
		if err != nil {
			return nil, fmt.Errorf("Error conveting point to byte: %v", err)
		} 
		token.Signature = partSigBytes

		// Define the new struct
		newToken = &Token{
			Nested:		token,
			Payload:	newPayload,	
		}

		// Marshal to JSON
		tmpToSign, err := json.Marshal(newToken)
		if err != nil {
			return nil, fmt.Errorf("Error generating json: %v\n", err)
		} 

		// Sign with aggKey key
		newSig := schoco.StdSign(fmt.Sprintf("%s", tmpToSign), aggKey)
		s, err = newSig.ToByte()
		if err != nil {
			return nil, fmt.Errorf("Error generating signed assertion: %v\n", err)
		} 
		// Set extToken signature
		newToken.Signature = s

		// // Encode signed Token
		// outToken, err = Encode(newToken)
		// if err != nil {
		// 	return "", fmt.Errorf("Error encoding Token: %v\n", err)
		// } 
		}
	return newToken, nil
}

// Validate the given Token, that can be using ID or anonymous mode, following version definition on spec document.
// TODO: retrieve the public key from iss.id (?)
// TODO: validate iss.id (actually, all places that use .id must validate the root. 
// We can assume using bundle to validate any root)
// 
// Current validation steps:
// 1 - Check Aud_{n} == Iss_{n+1} 
// 2 - Get PK from iss.PK 
// 3 - Validate signature
// 4 - Validate inner most using bundle (root LSVID)
// TODO: 
// 2 - Get PK from iss.id.nested.payload.sub.pk
// 4 - Validate also issuer bundle
// 
func Validate(token *Token, version int8, bundle ...*Token) (bool, error) {

    switch version {
	case 0:
		// Validate ID Mode with ECDSA

		for (token.Nested != nil) {

			// Check Aud -> Iss link
			if token.Payload.Iss.CN != token.Nested.Payload.Aud.CN {
				return false, fmt.Errorf("Aud -> Iss link validation failed\n")
			}
			log.Printf("Aud -> Iss link validation successful!\n")

			// Marshal the Token struct into JSON
			tmpToken := &Token{
				Nested:		token.Nested,
				Payload:	token.Payload,
			}
			tokenJSON, err := json.Marshal(tmpToken)
			if err != nil {
			return false, fmt.Errorf("error marshaling Token to JSON: %v\n", err)
			}
			hash 	:= sha256.Sum256(tokenJSON)

			// Parse the public key
			issPk, err := x509.ParsePKIXPublicKey(token.Payload.Iss.PK)
			if err != nil {
				return false, fmt.Errorf("Failed to parse public key: %v\n", err)
			}

			// validate the signature
			log.Printf("Verifying signature created by %s\n", token.Payload.Iss.CN)
			verify := ecdsa.VerifyASN1(issPk.(*ecdsa.PublicKey), hash[:], token.Signature)
			if verify == false {
				log.Printf("\nSignature validation failed!\n\n")
				return false, nil
			}
			log.Printf("Signature validation successful!\n")

			// jump to nested token
			token = token.Nested
		}

		// reached the inner most Token. 
		// Marshal the bundle struct into JSON
		tmpToken := &Token{
			Payload:	token.Payload,
		}
		tokenJSON, err := json.Marshal(tmpToken)
		if err != nil {
		return false, fmt.Errorf("error marshaling Token to JSON: %v\n", err)
		}
		hash 	:= sha256.Sum256(tokenJSON)

		// Parse the public key
		subPk, err := x509.ParsePKIXPublicKey(bundle[0].Payload.Sub.PK)
		if err != nil {
			return false, fmt.Errorf("Failed to parse public key: %v\n", err)
		}
		// log.Printf("Public key to be used: %s", issPk)

		log.Printf("Verifying signature created by %s\n", bundle[0].Payload.Sub.CN)
		verify := ecdsa.VerifyASN1(subPk.(*ecdsa.PublicKey), hash[:], token.Signature)
		if verify == false {
			log.Printf("\nBundle signature validation failed!\n\n")
			return false, nil
		}

	case 1:
		// Validate anon mode with SchoCo

		// Collect partial sigs and messages from all nested tokens
		var	setPartSig	[]kyber.Point
		var lastSig		schoco.Signature
		var	setMsg		[]string
		
		for i := 0; token.Nested != nil; i++ {
			tmpToken := &Token{
				Nested:		token.Nested,
				Payload:	token.Payload,
			}

			// Marshal to JSON
			tokenJSON, err := json.Marshal(tmpToken)
			if err != nil {
				log.Printf("Error marshaling Token to JSON: %v\n", err)
			}
			// Collect signed message
			setMsg = append(setMsg, fmt.Sprintf("%s", tokenJSON))

			// Collect signature
			if i == 0 {
				lastSig, err = schoco.ByteToSignature(token.Signature)
				if err != nil {
					log.Printf("Error converting byte to signature: %v\n", err)
				}
			} else {
				setPartSig[i], err = schoco.ByteToPoint(token.Signature)
				if err != nil {
					log.Printf("Error converting byte to Point: %v\n", err)
				}
			}

			// jump to nested token
			token = token.Nested

		}

		// reach most inner token
		// Collect msg
		tmpToken := &Token{
			Payload:	token.Payload,
		}
		tokenJSON, err := json.Marshal(tmpToken)
		if err != nil {
			log.Printf("error marshaling Token to JSON: %v\n", err)
		}
		setMsg = append(setMsg, fmt.Sprintf("%s", tokenJSON))

		// collect partsig
		tmpPartSig, err := schoco.ByteToPoint(token.Signature)
		if err != nil {
			log.Printf("Error converting byte to Point: %v\n", err)
		}
		setPartSig = append(setPartSig, tmpPartSig)

		// collect root pk
		rootPK, err := schoco.ByteToPoint(token.Payload.Iss.PK)
		if err != nil {
			log.Printf("Error converting byte to Point: %v\n", err)
		}

		if !schoco.Verify(rootPK, setMsg, setPartSig, lastSig)	{
			log.Printf("Validate with schoco.Verify failed!\n")
		}
	}

	return true, nil
}