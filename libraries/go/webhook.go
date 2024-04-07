package standardwebhooks

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderWebhookID        string = "webhook-id"
	HeaderWebhookSignature string = "webhook-signature"
	HeaderWebhookTimestamp string = "webhook-timestamp"

	webhookSecretPrefix     string = "whsec_"
	webhookPublicKeyPrefix  string = "whsk_"
	webhookPrivateKeyPrefix string = "whpk_"
	HMAC = "hmac"
	ED25519 = "ed25519"
)

var base64enc = base64.StdEncoding

var tolerance time.Duration = 5 * time.Minute

var (
	ErrRequiredHeaders     = errors.New("missing required headers")
	ErrInvalidHeaders      = errors.New("invalid signature headers")
	ErrNoMatchingSignature = errors.New("no matching signature found")
	ErrMessageTooOld       = errors.New("message timestamp too old")
	ErrMessageTooNew       = errors.New("message timestamp too new")
)

type Webhook struct {
	key        []byte
	privateKey []byte
	publicKey  []byte
	// TODO: turn this into enum
	signingMethod string
}

type WebhookOptions struct {
	AsymmetricMethod string
}

func NewWebhook(secret string) (*Webhook, error) {
	key, err := base64enc.DecodeString(strings.TrimPrefix(secret, webhookSecretPrefix))
	if err != nil {
		return nil, fmt.Errorf("unable to create webhook, err: %w", err)
	}
	return &Webhook{
		key:           key,
		signingMethod: "hmac",
	}, nil
}

func NewAsymmetricVerificationWebhook(publicKey string, options *WebhookOptions) (*Webhook, error) {
	method := "ed25519"

	// For future, if we wish to allow more signing methods
	if options != nil && options.AsymmetricMethod != "" {
		method = options.AsymmetricMethod
	}

	publicKeyBytes, err := base64enc.DecodeString(strings.TrimPrefix(publicKey, webhookPublicKeyPrefix))
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return &Webhook{
		publicKey:     publicKeyBytes,
		signingMethod: method,
	}, nil
}

// We leave an options parameter here in case we wish to pass in additional details in the future
func NewAsymmetricSigningWebhook(privateKey string, options *WebhookOptions) (*Webhook, error) {
	method := "ed25519"

	if options != nil && options.AsymmetricMethod != "" {
		method = options.AsymmetricMethod
	}

	privateKeyBytes, err := base64enc.DecodeString(strings.TrimPrefix(privateKey, webhookPublicKeyPrefix))
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	return &Webhook{
		privateKey:    privateKeyBytes,
		signingMethod: method,
	}, nil
}

func NewWebhookRaw(secret []byte) (*Webhook, error) {
	return &Webhook{
		key: secret,
	}, nil
}

// Verify validates the payload against the webhook signature headers
// using the webhooks signing secret.
//
// Returns an error if the body or headers are missing/unreadable
// or if the signature doesn't match.
func (wh *Webhook) Verify(payload []byte, headers http.Header) error {
	if wh.publicKey == nil && wh.signingMethod ==  "ed25519" {
		return fmt.Errorf("need a public key to verify asymmetric key")
	}
	return wh.verify(payload, headers, true)
}

// VerifyIgnoringTimestamp validates the payload against the webhook signature headers
// using the webhooks signing secret.
//
// Returns an error if the body or headers are missing/unreadable
// or if the signature doesn't match.
//
// WARNING: This function does not check the signature's timestamp.
// We recommend using the `Verify` function instead.
func (wh *Webhook) VerifyIgnoringTimestamp(payload []byte, headers http.Header) error {
	return wh.verify(payload, headers, false)
}

func (wh *Webhook) verify(payload []byte, headers http.Header, enforceTolerance bool) error {
	msgId := headers.Get(HeaderWebhookID)
	msgSignature := headers.Get(HeaderWebhookSignature)
	msgTimestamp := headers.Get(HeaderWebhookTimestamp)
	if msgId == "" || msgSignature == "" || msgTimestamp == "" {
		return fmt.Errorf("unable to verify payload, err: %w", ErrRequiredHeaders)
	}

	timestamp, err := parseTimestampHeader(msgTimestamp)
	if err != nil {
		return fmt.Errorf("unable to verify payload, err: %w", err)
	}

	if enforceTolerance {
		if err := verifyTimestamp(timestamp); err != nil {
			return fmt.Errorf("unable to verify payload, err: %w", err)
		}
	}

	// If this is asymmetric, verify using asymmetric keyset
	_, expectedSignature, err := wh.sign(msgId, timestamp, payload)
	if err != nil {
		return fmt.Errorf("unable to verify payload, err: %w", err)
	}

	passedSignatures := strings.Split(msgSignature, " ")
	for _, versionedSignature := range passedSignatures {
		sigParts := strings.Split(versionedSignature, ",")

		if len(sigParts) < 2 {
			continue
		}

		version := sigParts[0]
		signature := []byte(sigParts[1])

		if version == "v1" {
			if hmac.Equal(signature, expectedSignature) {
				return nil
			}
		} else if version == "v1a" { // ED25519
			toVerify := fmt.Sprintf("%s.%d.%s", msgId, msgTimestamp, payload)
			if ed25519.Verify(wh.publicKey, []byte(toVerify), signature) {
				return nil
			}
		} else {
			// or return an error
			continue
		}

		if hmac.Equal(signature, expectedSignature) {
			return nil
		}
	}

	return fmt.Errorf("unable to verify payload, err: %w", ErrNoMatchingSignature)
}

func (wh *Webhook) Sign(msgId string, timestamp time.Time, payload []byte) (string, error) {
	version, signature, err := wh.sign(msgId, timestamp, payload)
	return fmt.Sprintf("%s,%s", version, signature), err
}

func (wh *Webhook) sign(msgId string, timestamp time.Time, payload []byte) (version string, signature []byte, err error) {
	toSign := fmt.Sprintf("%s.%d.%s", msgId, timestamp.Unix(), payload)
	switch wh.signingMethod {
	// TODO: conver this to constant
	case HMAC:
		h := hmac.New(sha256.New, wh.key)
		h.Write([]byte(toSign))
		sig := h.Sum(nil)
		base64Sig := make([]byte, base64.StdEncoding.EncodedLen(len(sig)))
		base64.StdEncoding.Encode(base64Sig, sig)
		return "v1", base64Sig, nil

	case ED25519:
		if ed25519.PrivateKey(wh.privateKey).Seed() == nil {
			return "", nil, fmt.Errorf("invalid ED25519 private key")
		}
		sig := ed25519.Sign(wh.privateKey, []byte(toSign))

		base64Sig := make([]byte, base64.StdEncoding.EncodedLen(len(sig)))
		base64.StdEncoding.Encode(base64Sig, sig)
		return "v1a", base64Sig, nil

	default:
		return "", nil, fmt.Errorf("unsupported signing method")
	}

}

func parseTimestampHeader(timestampHeader string) (time.Time, error) {
	timeInt, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("unable to parse timestamp header, err: %w", errors.Join(err, ErrInvalidHeaders))
	}
	timestamp := time.Unix(timeInt, 0)
	return timestamp, nil
}

func verifyTimestamp(timestamp time.Time) error {
	now := time.Now()

	if now.Sub(timestamp) > tolerance {
		return ErrMessageTooOld
	}

	if timestamp.After(now.Add(tolerance)) {
		return ErrMessageTooNew
	}

	return nil
}
