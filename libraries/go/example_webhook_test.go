package standardwebhooks_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"time"

	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"
)

const (
	secretKey = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
)

// Example_signatureFlow describes the full flow of signature and verification
// of a webhook payload by verifying the timestamp also.
func Example_signatureFlow() {
	var (
		ts = time.Now()
		id = "1234567890"
	)

	wh, err := standardwebhooks.NewWebhook(secretKey)
	if err != nil {
		log.Fatal(err)
	}

	payload := `{"type": "example.created", "timestamp":"2023-09-28T19:20:22+00:00", "data":{"str":"string","bool":true,"int":42}}`

	// signing the payload with the webhook handler
	signature, err := wh.Sign(id, ts, []byte(payload))
	if err != nil {
		log.Fatal(err)
	}

	// generating the http header carrier
	header := http.Header{}
	header.Set(standardwebhooks.HeaderWebhookID, id)
	header.Set(standardwebhooks.HeaderWebhookSignature, signature)
	header.Set(standardwebhooks.HeaderWebhookTimestamp, fmt.Sprint(ts.Unix()))

	// http request is sent to consumer

	// consumer verifies the signature
	err = wh.Verify([]byte(payload), header)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("done")
	// Output: done
}
func generateEd25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func Example_asymmetricSignatureFlow() {
	pubKey, privKey, err := generateEd25519Keys()
	if err != nil {
		log.Fatalf("failed to generate Ed25519 keys: %v", err)
	}

	// Convert the private key into the format expected by WebhookOptions
	options := &standardwebhooks.WebhookOptions{
		KeyObject: standardwebhooks.KeyObject{
			KeyObjectType: standardwebhooks.PrivateKeyType,
			Key:           privKey,
		},
	}

	wh, err := standardwebhooks.NewWebhookWithOptions(standardwebhooks.ED25519, options)
	if err != nil {
		log.Fatalf("failed to create webhook with options: %v", err)
	}

	var (
		ts      = time.Now()
		id      = "1234567890"
		payload = `{"type": "example.created", "timestamp":"2023-09-28T19:20:22+00:00", "data":{"str":"string","bool":true,"int":42}}`
	)

	signature, err := wh.Sign(id, ts, []byte(payload))
	if err != nil {
		log.Fatalf("failed to sign payload: %v", err)
	}

	// Generating the HTTP header carrier with base64 encoded signature
	header := http.Header{}
	header.Set(standardwebhooks.HeaderWebhookID, id)
	header.Set(standardwebhooks.HeaderWebhookSignature, fmt.Sprintf("%s", signature))
	header.Set(standardwebhooks.HeaderWebhookTimestamp, fmt.Sprint(ts.Unix()))

	verifyOptions := &standardwebhooks.WebhookOptions{
		KeyObject: standardwebhooks.KeyObject{
			KeyObjectType: standardwebhooks.PublicKeyType,
			Key:           pubKey,
		},
	}
	verifyWh, err := standardwebhooks.NewWebhookWithOptions(standardwebhooks.ED25519, verifyOptions)
	if err != nil {
		log.Fatalf("failed to create verification webhook with options: %v", err)
	}

	err = verifyWh.Verify([]byte(payload), header)
	if err != nil {
		log.Fatalf("failed to verify payload: %v", err)
	}

	fmt.Println("done")
	// Output: done
}
