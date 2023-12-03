package nestedtoken_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"crypto/x509"

	"github.com/hpe-usp-spire/nestedtoken"
)

func generateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	return privateKey
}

func TestEncoding(t *testing.T) {
	// Creating a sample Token
	sampleToken := &nestedtoken.Token{
		Payload: &nestedtoken.Payload{
			Ver: 1,
			Iat: time.Now().Unix(),
			Iss: &nestedtoken.IDClaim{
				CN: "example.org",
				PK: []byte("Issuer_public_key"),
				ID: nil,
			},
			Aud: &nestedtoken.IDClaim{
				CN: "audience.example",
				PK: []byte("audience_public_key"),
				ID: nil,
			},
			Data: map[string]interface{}{
				"custom_claim": "custom_value",
			},
		},
	}

	// Encode the sample Token
	encodedToken, err := nestedtoken.Encode(sampleToken)
	if err != nil {
		t.Errorf("Encode failed: %v", err)
	}
	t.Logf("Encoded token: %s\n", encodedToken)

	// Decode the encoded token to verify integrity
	decodedTokenJSON, err := base64.RawURLEncoding.DecodeString(encodedToken)
	if err != nil {
		t.Errorf("Error decoding token: %v", err)
	}

	var decodedToken nestedtoken.Token
	err = json.Unmarshal(decodedTokenJSON, &decodedToken)
	if err != nil {
		t.Errorf("Error unmarshaling token: %v", err)
	}

	// Verify that the decodedToken matches the original sampleToken
	// Usage of reflect is interesting when dealing with complex structs
	if !reflect.DeepEqual(sampleToken, &decodedToken) {
		t.Error("Decoded token does not match the original token")
	}
}

func TestSingleTokenValidation(t *testing.T) {
	privateKey := generateECDSAKey(t)

	pubkey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	payload :=  &nestedtoken.Payload{
		Ver: 1,
		Iat: time.Now().Unix(),
		Iss: &nestedtoken.IDClaim{
			CN: "example.org",
			PK: pubkey,
		},
		Aud: &nestedtoken.IDClaim{
			CN: "audience.example",
			PK: []byte("audience_public_key"),
		},
		Sub:  &nestedtoken.IDClaim{
			CN: "example.org",
			PK: pubkey,
		},
		Data: map[string]interface{}{
			"custom_claim": "custom_value",
		},
	}

	createdToken, err := nestedtoken.Create(payload, privateKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}
	t.Logf("Created token: %s\n", createdToken)

	decodedToken, err := nestedtoken.Decode(createdToken)
	if err != nil {
		t.Fatalf("Failed to decode token: %v", err)
	}

	// validate token
	valid, err := nestedtoken.Validate(decodedToken, decodedToken)
	if err != nil {
		t.Fatalf("Failed to decode token: %v", err)
	}
	if valid != true {
		t.Fatalf("Failed to validate token")
	}

}

func TestExtendValidate(t *testing.T) {
	// Generating a sample token for testing
	privateKey := generateECDSAKey(t)

	pubkey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	payload := &nestedtoken.Payload{
		Ver: 1,
		Iat: time.Now().Unix(),
		Iss: &nestedtoken.IDClaim{
			CN: "Workload A",
			PK: pubkey,
		},
		Aud: &nestedtoken.IDClaim{
			CN: "Workload B",
			PK: []byte("audience_public_key"),
		},
		Sub: &nestedtoken.IDClaim{
			CN: "Workload A",
			PK: pubkey,
		},
		Data: map[string]interface{}{
			"custom_claim": "custom_value",
		},
	}

	createdToken, err := nestedtoken.Create(payload, privateKey)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}
	t.Logf("Created token: %s\n", createdToken)

	decodedToken, err := nestedtoken.Decode(createdToken)
	if err != nil {
		t.Fatalf("Failed to decode token: %v", err)
	}

	// Prepare a new payload
	newPayload := &nestedtoken.Payload{
		Ver: 2,
		Iat: time.Now().Unix(),
		Iss: &nestedtoken.IDClaim{
			CN: "Workload B",
			PK: pubkey,
		},
		Aud: &nestedtoken.IDClaim{
			CN: "Workload C",
			PK: []byte("audience_public_key"),
		},
		Data: map[string]interface{}{
			"updated_claim": "updated_value",
		},
	}

	// Extend the token
	extendedToken, err := nestedtoken.Extend(decodedToken, newPayload, privateKey)
	if err != nil {
		t.Fatalf("Failed to extend token: %v", err)
	}
	t.Logf("Extended token: %s\n", extendedToken)

	// Decode the extended token
	decodedExtendedToken, err := nestedtoken.Decode(extendedToken)
	if err != nil {
		t.Fatalf("Failed to decode extended token: %v", err)
	}

	// validate token
	valid, err := nestedtoken.Validate(decodedExtendedToken, decodedToken)
	if err != nil {
		t.Fatalf("Failed to decode token: %v", err)
	}
	if valid != true {
		t.Fatalf("Failed to validate token")
	}

}
