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

type WebhookMethod string
type KeyType string
type AsymmetricKeyType string
type SigningMethod string

const (
	HeaderWebhookID        string = "webhook-id"
	HeaderWebhookSignature string = "webhook-signature"
	HeaderWebhookTimestamp string = "webhook-timestamp"

	webhookSecretPrefix     string        = "whsec_"
	webhookPublicKeyPrefix  string        = "whpk_"
	webhookPrivateKeyPrefix string        = "whsk_"
	secretKeyType           KeyType       = "secret"
	publicKeyType           KeyType       = "public"
	privateKeyType          KeyType       = "private"
	HMAC                    WebhookMethod = "hmac"
	ED25519                 WebhookMethod = "ed25519"
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
	key     []byte
	method  WebhookMethod
	options *WebhookOptions
}

type WebhookOptions struct {
	keyObject KeyObject
}

type KeyObject struct {
	keyObjectType KeyType
	key           []byte
}

func NewWebhook(secret string) (*Webhook, error) {
	key, err := base64enc.DecodeString(strings.TrimPrefix(secret, webhookSecretPrefix))
	if err != nil {
		return nil, fmt.Errorf("unable to create webhook, err: %w", err)
	}
	return NewWebhookWithOptions(HMAC, &WebhookOptions{
		KeyObject{
			keyObjectType: "secret",
			key:           key,
		},
	})
}

func NewWebhookRaw(secret []byte) (*Webhook, error) {
	return &Webhook{
		key: secret,
	}, nil
}

func NewWebhookWithOptions(method WebhookMethod, options *WebhookOptions) (*Webhook, error) {
	return &Webhook{
		// TODO: Check that the keyObject indeed exists, else return an error
		key:     options.keyObject.key,
		method:  method,
		options: options,
	}, nil
}

// Verify validates the payload against the webhook signature headers
// using the webhooks signing secret.
//
// Returns an error if the body or headers are missing/unreadable
// or if the signature doesn't match.
func (wh *Webhook) Verify(payload []byte, headers http.Header) error {
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

	passedSignatures := strings.Split(msgSignature, " ")

	for _, versionedSignature := range passedSignatures {
		sigParts := strings.Split(versionedSignature, ",")
		if len(sigParts) < 2 {
			continue
		}
		version := sigParts[0]
		if version != "v1" {
			continue
		}
		signature := []byte(sigParts[1])
		switch version {
		case "v1":
			if wh.method != HMAC {
				continue
			}

			_, expectedSignature, err := wh.sign(msgId, timestamp, payload)
			if err != nil {
				return fmt.Errorf("unable to verify payload, err: %w", err)
			}

			if hmac.Equal(signature, expectedSignature) {
				return nil
			}
		case "v1a": // Ed25519 verification
			if wh.method != ED25519 || wh.options == nil || wh.options.keyObject.keyObjectType != "public" {
				continue
			}
			toSign := fmt.Sprintf("%s.%d.%s", msgId, timestamp.Unix(), string(payload))

			pubKey := ed25519.PublicKey(wh.options.keyObject.key)
			if ed25519.Verify(pubKey, []byte(toSign), signature) {
				return nil
			}
		}
	}

	return fmt.Errorf("unable to verify payload, err: %w", ErrNoMatchingSignature)
}

func (wh *Webhook) Sign(msgId string, timestamp time.Time, payload []byte) (string, error) {
	version, signature, err := wh.sign(msgId, timestamp, payload)
	return fmt.Sprintf("%s,%s", version, signature), err
}

func parseTimestampHeader(timestampHeader string) (time.Time, error) {
	timeInt, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("unable to parse timestamp header, err: %w", errors.Join(err, ErrInvalidHeaders))
	}
	timestamp := time.Unix(timeInt, 0)
	return timestamp, nil
}

func (wh *Webhook) sign(msgId string, timestamp time.Time, payload []byte) (version string, signature []byte, err error) {
	toSign := fmt.Sprintf("%s.%d.%s", msgId, timestamp.Unix(), string(payload))
	switch wh.method {
	case HMAC:
		h := hmac.New(sha256.New, wh.key)
		h.Write([]byte(toSign))
		sig := h.Sum(nil)
		base64Sig := make([]byte, base64enc.EncodedLen(len(sig)))
		base64enc.Encode(base64Sig, sig)
		return "v1", base64Sig, nil
	case ED25519:
		if wh.options == nil || wh.options.keyObject.keyObjectType != "private" {
			return "", nil, fmt.Errorf("invalid key configuration for asymmetric signing")
		}
		privKey := ed25519.PrivateKey(wh.options.keyObject.key)
		sig := ed25519.Sign(privKey, []byte(toSign))
		base64Sig := make([]byte, base64enc.EncodedLen(len(sig)))
		base64enc.Encode(base64Sig, sig)
		return "v1a", base64Sig, nil
	default:
		return "", nil, fmt.Errorf("unsupported signing method")
	}
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
