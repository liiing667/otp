/**
 *  Copyright 2014 Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package hotp

import (
	"github.com/pquerna/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"encoding/base32"
	"io"
	"testing"
)

type tc struct {
	Counter uint64
	TOTP    string
	Mode    otp.Algorithm
	Secret  string
}

var (
	secSha1 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	rfcMatrixTCs = []tc{
		{0, "755224", otp.AlgorithmSHA1, secSha1},
		{1, "287082", otp.AlgorithmSHA1, secSha1},
		{2, "359152", otp.AlgorithmSHA1, secSha1},
		{3, "969429", otp.AlgorithmSHA1, secSha1},
		{4, "338314", otp.AlgorithmSHA1, secSha1},
		{5, "254676", otp.AlgorithmSHA1, secSha1},
		{6, "287922", otp.AlgorithmSHA1, secSha1},
		{7, "162583", otp.AlgorithmSHA1, secSha1},
		{8, "399871", otp.AlgorithmSHA1, secSha1},
		{9, "520489", otp.AlgorithmSHA1, secSha1},
	}
)

// Test values from http://tools.ietf.org/html/rfc4226#appendix-D
func TestValidateRFCMatrix(t *testing.T) {

	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.TOTP, tx.Counter, tx.Secret,
			ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: tx.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v counter=%v", tx.TOTP, tx.Mode, tx.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v counter=%v", tx.TOTP, tx.Mode, tx.Counter)
	}
}

func TestGenerateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, tx.Counter,
			ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: tx.Mode,
			})
		assert.Nil(t, err)
		assert.Equal(t, tx.TOTP, passcode)
	}
}

func TestGenerateCodeCustom(t *testing.T){
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	code, err := GenerateCodeCustom("foo",1,ValidateOpts{})
	print(code)
	require.Equal(t, otp.ErrValidateSecretInvalidBase32, err, "Decoding of secret as base32 failed.")
	require.Equal(t, "", code, "Code should be empty string when we have an error.")

	code, err = GenerateCodeCustom(secSha1,1,ValidateOpts{})
	require.Equal(t, 6, len(code), "Code should be 6 digits when we have not an error.")
	require.NoError(t, err, "Expected no error.")
}

func TestValidateInvalid(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	valid, err := ValidateCustom("foo", 11, secSha1,
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
	})
	require.Equal(t, otp.ErrValidateInputInvalidLength, err, "Expected Invalid length error.")
	require.Equal(t, false, valid, "Valid should be false when we have an error.")

	valid, err = ValidateCustom("foo", 11, secSha1,
		ValidateOpts{
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.Equal(t, otp.ErrValidateInputInvalidLength, err, "Expected Invalid length error.")
	require.Equal(t, false, valid, "Valid should be false when we have an error.")

	valid, err = ValidateCustom("000000", 11, secSha1,
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.NoError(t, err, "Expected no error.")
	require.Equal(t, false, valid, "Valid should be false.")

	valid = Validate("000000", 11, secSha1)
	require.Equal(t, false, valid, "Valid should be false.")
}

func TestGenerateCodeCustomUnsupportedEncoder(t *testing.T) {
	// An unknown encoder must return an error instead of an empty passcode.
	code, err := GenerateCodeCustom(secSha1, 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Encoder:   otp.Encoder("rot13"),
	})
	require.Equal(t, otp.ErrUnsupportedEncoder, err, "unknown encoder rejected")
	require.Equal(t, "", code, "Code should be empty string when we have an error.")
}

// This tests for issue #10 - secrets without padding
func TestValidatePadding(t *testing.T) {
	valid, err := ValidateCustom("831097", 0, "JBSWY3DPEHPK3PX",
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.NoError(t, err, "Expected no error.")
	require.Equal(t, true, valid, "Valid should be true.")
}

func TestValidateLowerCaseSecret(t *testing.T) {
	valid, err := ValidateCustom("831097", 0, "jbswy3dpehpk3px",
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.NoError(t, err, "Expected no error.")
	require.Equal(t, true, valid, "Valid should be true.")
}

func TestGenerate(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err, "generate basic HOTP")
	require.Equal(t, "SnakeOil", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@example.com", k.AccountName(), "Extracting Account Name")
	require.Equal(t, 32, len(k.Secret()), "Default secret is otp.DefaultSecretSize (20 bytes -> 32 base32 chars).")
	require.Equal(t, otp.EncoderDefault, k.Encoder(), "Default encoder is the numeric RFC encoder.")

	k, err = Generate(GenerateOpts{
		Issuer:      "Snake Oil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err, "issuer with a space in the name")
	require.Contains(t, k.String(), "issuer=Snake%20Oil")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  20,
	})
	require.NoError(t, err, "generate larger HOTP")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

	k, err = Generate(GenerateOpts{
		Issuer:      "",
		AccountName: "alice@example.com",
	})
	require.Equal(t, otp.ErrGenerateMissingIssuer, err, "generate missing issuer")
	require.Nil(t, k, "key should be nil on error.")

	k, err = Generate(GenerateOpts{
		Issuer:      "Foobar, Inc",
		AccountName: "",
	})
	require.Equal(t, otp.ErrGenerateMissingAccountName, err, "generate missing account name.")
	require.Nil(t, k, "key should be nil on error.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  17, // >= MinSecretSize and not divisible by 5, really
	})
	require.NoError(t, err, "Secret size is valid when length not divisible by 5.")
	require.NotContains(t, k.Secret(), "=", "Secret has no escaped characters.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Secret:      []byte("helloworld-16byte"),
	})
	require.NoError(t, err, "Secret generation failed")
	sec, err := b32NoPadding.DecodeString(k.Secret())
	require.NoError(t, err, "Secret was not valid base32")
	require.Equal(t, sec, []byte("helloworld-16byte"), "Specified Secret was not kept")
}

func TestGenerateRejectsWeakSecrets(t *testing.T) {
	// A caller supplied secret below the 128-bit floor must fail closed.
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Secret:      []byte("helloworld"), // 10 bytes
	})
	require.Equal(t, otp.ErrWeakSecretSize, err, "short caller secret rejected")
	require.Nil(t, k, "key should be nil on error.")

	// Requesting a random secret below the floor must fail closed.
	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  otp.MinSecretSize - 1,
	})
	require.Equal(t, otp.ErrWeakSecretSize, err, "small SecretSize rejected")
	require.Nil(t, k, "key should be nil on error.")

	// The floor itself remains accepted.
	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  otp.MinSecretSize,
	})
	require.NoError(t, err, "MinSecretSize is a valid secret size.")
	sec, err := b32NoPadding.DecodeString(k.Secret())
	require.NoError(t, err)
	require.Len(t, sec, otp.MinSecretSize, "Secret is exactly MinSecretSize bytes.")
}

func TestGenerateRandShortReadFails(t *testing.T) {
	// A reader that never returns data must surface an error rather than a
	// partially randomized secret ending up in the otpauth URI / QR code.
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Rand:        zeroReader{},
	})
	require.Error(t, err, "short random read rejected")
	require.Nil(t, k, "key should be nil on error.")
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func TestGenerateEncodingPolicy(t *testing.T) {
	// Steam requires five digits and exports its encoder into the URI.
	k, err := Generate(GenerateOpts{
		Issuer:      "Steam",
		AccountName: "alice@example.com",
		Digits:      otp.DigitsFive,
		Encoder:     otp.EncoderSteam,
	})
	require.NoError(t, err, "steam encoder with five digits accepted")
	require.Equal(t, otp.EncoderSteam, k.Encoder(), "encoder preserved on the key")
	require.Contains(t, k.String(), "encoder=steam", "encoder exported into the otpauth URI")
	require.Equal(t, otp.DigitsFive, k.Digits(), "digits preserved on the key")

	// Steam is not valid with the default six digit length.
	k, err = Generate(GenerateOpts{
		Issuer:      "Steam",
		AccountName: "alice@example.com",
		Encoder:     otp.EncoderSteam,
	})
	require.Equal(t, otp.ErrInvalidDigits, err, "steam encoder requires five digits")
	require.Nil(t, k, "key should be nil on error.")

	// Unknown encoders fail closed instead of producing empty passcodes.
	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Encoder:     otp.Encoder("rot13"),
	})
	require.Equal(t, otp.ErrUnsupportedEncoder, err, "unknown encoder rejected")
	require.Nil(t, k, "key should be nil on error.")
}
