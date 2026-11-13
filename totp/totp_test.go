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

package totp

import (
	"github.com/pquerna/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"encoding/base32"
	"math"
	"testing"
	"time"
)

type tc struct {
	TS     int64
	TOTP   string
	Mode   otp.Algorithm
	Secret string
}

var (
	secSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCs = []tc{
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "46119246", otp.AlgorithmSHA256, secSha256},
		{59, "90693936", otp.AlgorithmSHA512, secSha512},
		{1111111109, "07081804", otp.AlgorithmSHA1, secSha1},
		{1111111109, "68084774", otp.AlgorithmSHA256, secSha256},
		{1111111109, "25091201", otp.AlgorithmSHA512, secSha512},
		{1111111111, "14050471", otp.AlgorithmSHA1, secSha1},
		{1111111111, "67062674", otp.AlgorithmSHA256, secSha256},
		{1111111111, "99943326", otp.AlgorithmSHA512, secSha512},
		{1234567890, "89005924", otp.AlgorithmSHA1, secSha1},
		{1234567890, "91819424", otp.AlgorithmSHA256, secSha256},
		{1234567890, "93441116", otp.AlgorithmSHA512, secSha512},
		{2000000000, "69279037", otp.AlgorithmSHA1, secSha1},
		{2000000000, "90698825", otp.AlgorithmSHA256, secSha256},
		{2000000000, "38618901", otp.AlgorithmSHA512, secSha512},
		{20000000000, "65353130", otp.AlgorithmSHA1, secSha1},
		{20000000000, "77737706", otp.AlgorithmSHA256, secSha256},
		{20000000000, "47863826", otp.AlgorithmSHA512, secSha512},
	}
)

//
// Test vectors from http://tools.ietf.org/html/rfc6238#appendix-B
// NOTE -- the test vectors are documented as having the SAME
// secret -- this is WRONG -- they have a variable secret
// depending upon the hmac algorithm:
// 		http://www.rfc-editor.org/errata_search.php?rfc=6238
// this only took a few hours of head/desk interaction to figure out.
//
func TestValidateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
	}
}

func TestGenerateRFCTCs(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		assert.Nil(t, err)
		assert.Equal(t, tx.TOTP, passcode)
	}
}

func TestValidateSkew(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	tests := []tc{
		{29, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{61, "94287082", otp.AlgorithmSHA1, secSha1},
	}

	for _, tx := range tests {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
				Skew:      1,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
	}
}

func TestGenerate(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
	})
	require.NoError(t, err, "generate basic TOTP")
	require.Equal(t, "SnakeOil", k.Issuer(), "Extracting Issuer")
	require.Equal(t, "alice@example.com", k.AccountName(), "Extracting Account Name")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

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
	require.NoError(t, err, "generate larger TOTP")
	require.Equal(t, 32, len(k.Secret()), "Secret is 32 bytes long as base32.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  13, // anything that is not divisible by 5, really
	})
	require.NoError(t, err, "Secret size is valid when length not divisible by 5.")
	require.NotContains(t, k.Secret(), "=", "Secret has no escaped characters.")

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Secret:      []byte("helloworld"),
	})
	require.NoError(t, err, "Secret generation failed")
	sec, err := b32NoPadding.DecodeString(k.Secret())
	require.NoError(t, err, "Secret wa not valid base32")
	require.Equal(t, sec, []byte("helloworld"), "Specified Secret was not kept")
}

func TestGoogleLowerCaseSecret(t *testing.T) {
	w, err := otp.NewKeyFromURL(`otpauth://totp/Google%3Afoo%40example.com?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&issuer=Google`)
	require.NoError(t, err)
	sec := w.Secret()
	require.Equal(t, "qlt6vmy6svfx4bt4rpmisaiyol6hihca", sec)

	n := time.Now().UTC()
	code, err := GenerateCode(w.Secret(), n)
	require.NoError(t, err)

	valid := Validate(code, w.Secret())
	require.True(t, valid)
}

func TestSteamSecret(t *testing.T) {
	w, err := otp.NewKeyFromURL(`otpauth://totp/username%20steam:username?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&period=30&digits=5&issuer=username%20steam&encoder=steam`)
	require.NoError(t, err)
	require.Equal(t, "qlt6vmy6svfx4bt4rpmisaiyol6hihca", w.Secret())
	require.Equal(t, otp.EncoderSteam, w.Encoder())
	require.Equal(t, 5, w.Digits().Length())

	n := time.Now().UTC()
	opts := ValidateOpts{
		Period:  uint(w.Period()),
		Digits:  w.Digits(),
		Encoder: w.Encoder(),
	}
	code, err := GenerateCodeCustom(w.Secret(), n, opts)
	require.NoError(t, err)

	require.Len(t, code, w.Digits().Length())

	valid, err := ValidateCustom(code, w.Secret(), n, opts)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestValidateCustomCounterRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		opts := ValidateOpts{
			Digits:    otp.DigitsEight,
			Algorithm: tx.Mode,
		}
		expected := uint64(math.Floor(float64(tx.TS) / float64(30)))

		counter, valid, err := ValidateCustomCounter(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(), opts)
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.Equal(t, expected, counter,
			"matched time-step counter should be reported back totp=%s", tx.TOTP)
	}
}

func TestValidateCustomCounterSkew(t *testing.T) {
	opts := ValidateOpts{
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
		Skew:      1,
	}

	// The passcode 94287082 is generated for time-step 1 (TS 59), but the
	// validation time TS 89 belongs to time-step 2. With Skew of 1 the
	// previous step still matches, and the matched counter must be reported.
	baseCounter := uint64(1)
	tests := []struct {
		ts      int64
		current uint64
		matched uint64
	}{
		{29, 0, 1},  // next time-step accepted via skew
		{59, 1, 1},  // current time-step
		{89, 2, 1},  // previous time-step accepted via skew
	}

	for _, tx := range tests {
		counter, valid, err := ValidateCustomCounter("94287082", secSha1, time.Unix(tx.ts, 0).UTC(), opts)
		require.NoError(t, err, "unexpected error at ts=%v", tx.ts)
		require.True(t, valid, "unexpected totp failure at ts=%v", tx.ts)
		require.Equal(t, tx.matched, counter, "matched counter at ts=%v", tx.ts)
		require.Equal(t, baseCounter, counter, "same code must resolve to the same time-step")
		require.Equal(t, tx.current, uint64(tx.ts/30), "sanity check of the current time-step")
	}
}

func TestValidateCustomCounterNoMatch(t *testing.T) {
	counter, valid, err := ValidateCustomCounter("00000000", secSha1, time.Unix(59, 0).UTC(),
		ValidateOpts{
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.NoError(t, err, "Expected no error.")
	require.False(t, valid, "Valid should be false.")
	require.Equal(t, uint64(0), counter, "Counter should be zero when no match is found.")
}

func TestValidateCustomCounterErrorClassification(t *testing.T) {
	counter, valid, err := ValidateCustomCounter("foo", secSha1, time.Unix(59, 0).UTC(),
		ValidateOpts{
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA1,
		})
	require.Equal(t, otp.ErrValidateInputInvalidLength, err, "Expected Invalid length error.")
	require.False(t, valid, "Valid should be false when we have an error.")
	require.Equal(t, uint64(0), counter, "Counter should be zero when we have an error.")
}

func TestValidateCustomCounterReplayProtection(t *testing.T) {
	opts := ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	}

	// Generate a code for time-step 10 and validate it while on time-step 11,
	// exercising the skew window. The server persists the matched counter (10).
	code, err := GenerateCodeCustom(secSha1, time.Unix(10*30, 0).UTC(), opts)
	require.NoError(t, err)

	lastConsumed, valid, err := ValidateCustomCounter(code, secSha1, time.Unix(11*30, 0).UTC(), opts)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(10), lastConsumed)

	// Re-submitting the same passcode while still inside the validity/skew
	// window succeeds at the library level, but the server can now reject it
	// because the matched counter is not greater than the consumed one.
	matched, valid, err := ValidateCustomCounter(code, secSha1, time.Unix(11*30, 0).UTC(), opts)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, lastConsumed, matched)
	require.True(t, matched <= lastConsumed,
		"replayed passcode must be rejectable via the persisted counter %v", lastConsumed)

	// A fresh time-step produces a strictly greater, acceptable counter.
	nextCode, err := GenerateCodeCustom(secSha1, time.Unix(12*30, 0).UTC(), opts)
	require.NoError(t, err)
	matched, valid, err = ValidateCustomCounter(nextCode, secSha1, time.Unix(12*30, 0).UTC(), opts)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(12), matched)
	require.True(t, matched > lastConsumed,
		"next counter %v must exceed the consumed counter %v", matched, lastConsumed)
}
