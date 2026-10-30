package bundleformat

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestBytes(t *testing.T) {
	const (
		certPEM = `-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv
sCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs
RxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X
makw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA
dZglS5kKnYigmwDh+/U=
-----END CERTIFICATE-----
`
	)
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "unable to unmarshal certificate response: malformed PEM block")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	keyPkix, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	testBundle := &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: cert.Raw}},
		JwtAuthorities: []*types.JWTKey{
			{
				KeyId:     "KID",
				PublicKey: keyPkix,
			},
		},
		RefreshHint:    1440,
		SequenceNumber: 100,
	}
	standardJWKS := `{"keys":[{%s"kty":"EC","crv":"P-256","x":"fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4","y":"wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI","x5c":["MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="]},{%s"kty":"EC","kid":"KID","crv":"P-256","x":"fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4","y":"wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"}]%s}`
	expectedJWKS := fmt.Sprintf(standardJWKS, "", "", "")
	expectedSPIFFEBundle := fmt.Sprintf(standardJWKS, `"use":"x509-svid",`, `"use":"jwt-svid",`, `,"spiffe_sequence":100,"spiffe_refresh_hint":1440`)

	for _, tt := range []struct {
		name        string
		format      Format
		bundle      *types.Bundle
		expectBytes []byte
		expectError string
	}{
		{
			name:        "format not set",
			bundle:      testBundle,
			expectError: "no format specified",
		},
		{
			name:        "invalid format",
			format:      math.MaxInt,
			bundle:      testBundle,
			expectError: fmt.Sprintf("invalid format: \"UNKNOWN(%d)\"", math.MaxInt),
		},
		{
			name:        "no bundle",
			format:      SPIFFE,
			expectError: "missing bundle",
		},
		{
			name:        "jwks format",
			format:      JWKS,
			bundle:      testBundle,
			expectBytes: []byte(expectedJWKS),
		},
		{
			name:        "pem format",
			format:      PEM,
			bundle:      testBundle,
			expectBytes: []byte(certPEM),
		},
		{
			name:        "spiffe format",
			format:      SPIFFE,
			bundle:      testBundle,
			expectBytes: []byte(expectedSPIFFEBundle),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := NewFormatter(tt.bundle)

			if !proto.Equal(tt.bundle, b.bundle) {
				require.Equal(t, tt.bundle, b.bundle)
			}

			// Test the Format function that's provided by the formatter and
			// also test the FormatBundle function that should have the same
			// result.
			formatResult, formatErr := b.Format(tt.format)
			formatBundleResult, formatBundleErr := FormatBundle(tt.bundle, tt.format)
			if tt.expectError != "" {
				require.EqualError(t, formatErr, tt.expectError)
				require.Nil(t, formatResult)

				require.EqualError(t, formatBundleErr, tt.expectError)
				require.Nil(t, formatBundleResult)
				return
			}
			require.NoError(t, formatErr)
			require.NoError(t, formatBundleErr)

			require.Equal(t, string(tt.expectBytes), string(formatResult))
			require.Equal(t, string(tt.expectBytes), string(formatBundleResult))
		})
	}
}

func TestStringConversion(t *testing.T) {
	for _, tt := range []struct {
		name         string
		formatString string
		expectError  string
		expectFormat Format
	}{
		{
			name:         "invalid format",
			formatString: "INVALID",
			expectError:  `unknown bundle format: "INVALID"`,
		},
		{
			name:         "jwks format",
			formatString: "jwks",
			expectFormat: JWKS,
		},
		{
			name:         "pem format",
			formatString: "pem",
			expectFormat: PEM,
		},
		{
			name:         "spiffe format",
			formatString: "spiffe",
			expectFormat: SPIFFE,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			format, err := FromString(tt.formatString)
			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				require.Equal(t, FormatUnset, format)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectFormat, format)
			require.Equal(t, tt.formatString, format.String())
		})
	}
}

func TestMLDSAFormats(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pq bundle CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	keyPKIX, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)

	bundle := &types.Bundle{
		TrustDomain:     "pq.example",
		X509Authorities: []*types.X509Certificate{{Asn1: der}},
		JwtAuthorities:  []*types.JWTKey{{KeyId: "jwt-key", PublicKey: keyPKIX}},
		RefreshHint:     60,
		SequenceNumber:  7,
	}
	formatter := NewFormatter(bundle)

	spiffeBytes, err := formatter.Format(SPIFFE)
	require.NoError(t, err)
	require.Contains(t, string(spiffeBytes), `"kty":"AKP"`)
	require.Contains(t, string(spiffeBytes), `"alg":"ML-DSA-65"`)
	require.Contains(t, string(spiffeBytes), `"use":"x509-svid"`)
	require.Contains(t, string(spiffeBytes), `"use":"jwt-svid"`)
	require.NotContains(t, string(spiffeBytes), `"priv"`)

	jwksBytes, err := formatter.Format(JWKS)
	require.NoError(t, err)
	require.Contains(t, string(jwksBytes), `"kty":"AKP"`)
	require.NotContains(t, string(jwksBytes), `"use"`)

	pemBytes, err := formatter.Format(PEM)
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	_, ok := cert.PublicKey.(*mldsa.PublicKey)
	require.True(t, ok)
}
