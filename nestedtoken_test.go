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
	"github.com/hpe-usp-spire/schoco"
)

func generateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	return privateKey
}
func TestAll(t *testing.T){

	t.Run("Test Encoding", func(t *testing.T) {
		// Creating a sample Token
		sampleToken := &nestedtoken.Token{
			Payload: &nestedtoken.Payload{
				Ver: 0,
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
		t.Logf("\nEncoded token: %s\n", encodedToken)

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
	})

	t.Run("Test ECDSA single token creation and validation", func(t *testing.T) {
		privateKey := generateECDSAKey(t)

		pubkey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to marshal public key: %v", err)
		}

		payload :=  &nestedtoken.Payload{
			Ver: 0,
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

		createdToken, err := nestedtoken.Create(payload, 0, privateKey)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		encodedToken, err := nestedtoken.Encode(createdToken)
		if err != nil {
			t.Fatalf("Failed to encode token: %v", err)
		}
		t.Logf("\nEncoded token: %s\n", encodedToken)

		// validate token
		valid, err := nestedtoken.Validate(createdToken, 0, createdToken)
		if err != nil {
			t.Fatalf("Failed to decode token: %v", err)
		}
		if valid != true {
			t.Fatalf("Failed to validate token")
		}

	})

	t.Run("Test ECDSA extend and validate", func(t *testing.T) {
		// Generating a sample token for testing
		privateKey := generateECDSAKey(t)

		pubkey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to marshal public key: %v", err)
		}

		payload := &nestedtoken.Payload{
			Ver: 0,
			Iat: time.Now().Unix(),
			Iss: &nestedtoken.IDClaim{
				CN: "Workload A",
				PK: pubkey,
			},
			Aud: &nestedtoken.IDClaim{
				CN: "Workload B",
				PK: pubkey,
			},
			Sub: &nestedtoken.IDClaim{
				CN: "Workload A",
				PK: pubkey,
			},
			Data: map[string]interface{}{
				"custom_claim": "custom_value",
			},
		}

		createdToken, err := nestedtoken.Create(payload, 0, privateKey)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		// Prepare a new payload
		newPayload := &nestedtoken.Payload{
			Ver: 0,
			Iat: time.Now().Unix(),
			Iss: &nestedtoken.IDClaim{
				CN: "Workload B",
				PK: pubkey,
			},
			Aud: &nestedtoken.IDClaim{
				CN: "Workload C",
				PK: pubkey,
			},
			Data: map[string]interface{}{
				"updated_claim": "updated_value",
			},
		}

		// Extend the token
		extendedToken, err := nestedtoken.Extend(createdToken, newPayload, 0, privateKey)
		if err != nil {
			t.Fatalf("Failed to extend token: %v", err)
		}

		encodedToken, err := nestedtoken.Encode(extendedToken)
		if err != nil {
			t.Fatalf("Failed to encode token: %v", err)
		}
		t.Logf("\nEncoded token: %s\n", encodedToken)

		// validate token
		valid, err := nestedtoken.Validate(extendedToken, 0, createdToken)
		if err != nil {
			t.Fatalf("Failed to decode token: %v", err)
		}
		if valid != true {
			t.Fatalf("Failed to validate token")
		}

	})

	t.Run("Test Schoco creation and extension", func(t *testing.T) {	
	
		// creates random keypair
		secretKey, publicKey := schoco.RandomKeyPair()

		// convert publicKey to byte
		PubKeyBytes, err := schoco.PointToByte(publicKey)
		if err != nil {
			t.Fatalf("Error conveting point to byte: %v", err)
		} 

		payload :=  &nestedtoken.Payload{
			Ver: 1,
			Iat: time.Now().Unix(),
			Iss: &nestedtoken.IDClaim{
				PK: PubKeyBytes,
			},
			Data: map[string]interface{}{
				"custom_claim": "custom_value",
			},
		}

		// Create token using EdDSA key
		createdToken, err := nestedtoken.Create(payload, 1, secretKey)
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		// Prepare a new payload
		newPayload :=  &nestedtoken.Payload{
			Ver: 1,
			Iat: time.Now().Unix(),
			Data: map[string]interface{}{
				"newcustom_claim": "other_value",
			},
		}

		// Extend the token
		extendedToken, err := nestedtoken.Extend(createdToken, newPayload, 1)
		if err != nil {
			t.Fatalf("Failed to extend token: %v", err)
		}

		// validate token using version 1 (SchoCo)
		valid, err := nestedtoken.Validate(extendedToken, 1)
		if err != nil {
			t.Fatalf("Failed to decode token: %v", err)
		}
		if valid != true {
			t.Fatalf("Failed to validate token")
		}
		t.Logf("\nSchoCo validation successful!\n")

		encodedToken, err := nestedtoken.Encode(extendedToken)
		if err != nil {
			t.Fatalf("Failed to encode token: %v", err)
		}
		t.Logf("\nEncoded token: %s\n", encodedToken)


	})
}