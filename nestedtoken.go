package nestedtoken

// This package contains the main structs and functions to implement the nested token model using ID-mode, as specified in XYZ (UPDATE)
// Anonymous mode can be found in a separated package (INSERT REFERENCE)

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
)

// The token must contain a Payload and a Signature. 
// The Nested value is optional, and must be used when extending the token.
type Token struct {	
	Nested		*Token					`json:"nested,omitempty"`
	Payload		*Payload				`json:"payload"`
	Signature	[]byte					`json:"signature"`
}

// The mandatory claims are pre-defined. Any other info to be added must be inserted in Data.
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
func Create(newPayload *Payload, key crypto.Signer) (string, error) {

	newToken := &Token{
		Payload:	newPayload,	
	}

	// Marshal to JSON
	tmpToSign, err := json.Marshal(newToken)
	if err != nil {
		return "", fmt.Errorf("Error generating json: %v\n", err)
	} 

	// Sign Token
	hash 	:= sha256.Sum256(tmpToSign)
	s, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("Error generating signed assertion: %v\n", err)
	} 

	// Set Token signature
	newToken.Signature = s

	// Encode signed Token
	outToken, err := Encode(newToken)
	if err != nil {
		return "", fmt.Errorf("Error encoding Token: %v\n", err)
	} 

	return outToken, nil
}

// Extend an existing token with a new payload, and sign using provided key
func Extend(token *Token, newPayload *Payload, key crypto.Signer) (string, error) {
	// TODO: Modify the payload struct to support custom claims (maybe using map[string]{interface})
	// Create the extended Token structure

	newToken := &Token{
		Nested:		token,
		Payload:	newPayload,	
	}

	// Marshal to JSON
	tmpToSign, err := json.Marshal(newToken)
	if err != nil {
		return "", fmt.Errorf("Error generating json: %v\n", err)
	} 

	// Sign extlSVID
	hash 	:= sha256.Sum256(tmpToSign)
	s, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("Error generating signed assertion: %v\n", err)
	} 

	// Set extToken signature
	newToken.Signature = s

	// Encode signed Token
	outToken, err := Encode(newToken)
	if err != nil {
		return "", fmt.Errorf("Error encoding Token: %v\n", err)
	} 

	return outToken, nil

}

// Validate the given Token. 
// TODO: retrieve the public key from iss.id
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
func Validate(token *Token, bundle *Token) (bool, error) {

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
		Payload:	bundle.Payload,
	}
	tokenJSON, err := json.Marshal(tmpToken)
	if err != nil {
	return false, fmt.Errorf("error marshaling Token to JSON: %v\n", err)
	}
	hash 	:= sha256.Sum256(tokenJSON)

	// Parse the public key
	subPk, err := x509.ParsePKIXPublicKey(bundle.Payload.Sub.PK)
	if err != nil {
		return false, fmt.Errorf("Failed to parse public key: %v\n", err)
	}
	// log.Printf("Public key to be used: %s", issPk)

	log.Printf("Verifying signature created by %s\n", bundle.Payload.Sub.CN)
	verify := ecdsa.VerifyASN1(subPk.(*ecdsa.PublicKey), hash[:], token.Signature)
	if verify == false {
		log.Printf("\nBundle signature validation failed!\n\n")
		return false, nil
	}

	return true, nil
}