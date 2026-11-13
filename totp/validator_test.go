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
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/stretchr/testify/require"
)

// RFC 6238 appendix-B vectors must still validate and report the matched
// time-step; each vector uses a distinct time-step so none is a replay.
func TestValidatorRFCVectors(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		validator := NewValidator(tx.Secret, ValidateOpts{
			Period:    30,
			Digits:    otp.DigitsEight,
			Algorithm: tx.Mode,
		})

		valid, matched, err := validator.Validate(tx.TOTP, time.Unix(tx.TS, 0).UTC())
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)

		expected := uint64(tx.TS / 30)
		require.Equal(t, expected, matched)

		last, ok := validator.LastConsumed()
		require.True(t, ok)
		require.Equal(t, expected, last)
	}
}

// A passcode inside the skew window is consumed once; the second presentation
// is a replay and must not change the recorded time-step.
func TestValidatorSkewReplay(t *testing.T) {
	validator := NewValidator(secSha1, ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})

	// 94287082 is the code for time-step 1 (t=29..59). Present it at t=61,
	// where time-step 1 is the previous step inside the skew window.
	at := time.Unix(61, 0).UTC()

	valid, matched, err := validator.Validate("94287082", at)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), matched)

	valid, matched, err = validator.Validate("94287082", at)
	require.Equal(t, otp.ErrCodeReplayed, err)
	require.False(t, valid)
	require.Equal(t, uint64(1), matched)

	last, ok := validator.LastConsumed()
	require.True(t, ok)
	require.Equal(t, uint64(1), last)
}

// A wrong passcode must never record a consumed time-step.
func TestValidatorWrongCodeDoesNotAdvance(t *testing.T) {
	validator := NewValidator(secSha1, ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})

	valid, _, err := validator.Validate("00000000", time.Unix(59, 0).UTC())
	require.NoError(t, err)
	require.False(t, valid)

	_, ok := validator.LastConsumed()
	require.False(t, ok, "failed validation must not consume a time-step")

	// The real code for this time-step still works exactly once.
	valid, matched, err := validator.Validate("94287082", time.Unix(59, 0).UTC())
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(1), matched)
}

func TestValidatorInvalidLength(t *testing.T) {
	validator := NewValidator(secSha1, ValidateOpts{})

	valid, _, err := validator.Validate("12345", time.Now().UTC())
	require.Equal(t, otp.ErrValidateInputInvalidLength, err)
	require.False(t, valid)

	_, ok := validator.LastConsumed()
	require.False(t, ok)
}

func TestValidatorValidateNow(t *testing.T) {
	validator := NewValidator(secSha1, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})

	now := time.Now().UTC()
	code, err := GenerateCodeCustom(secSha1, now, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	valid, _, err := validator.ValidateNow(code)
	require.NoError(t, err)
	require.True(t, valid)

	valid, _, err = validator.ValidateNow(code)
	require.Equal(t, otp.ErrCodeReplayed, err)
	require.False(t, valid)
}

// Under contention exactly one goroutine may consume a time-step.
func TestValidatorConcurrentConsumption(t *testing.T) {
	validator := NewValidator(secSha1, ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})

	at := time.Unix(59, 0).UTC()

	const goroutines = 64
	var wg sync.WaitGroup
	results := make(chan error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			valid, _, err := validator.Validate("94287082", at)
			if valid {
				results <- nil
			} else {
				results <- err
			}
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	replays := 0
	for err := range results {
		switch err {
		case nil:
			successes++
		case otp.ErrCodeReplayed:
			replays++
		default:
			t.Fatalf("unexpected validation error: %v", err)
		}
	}

	require.Equal(t, 1, successes)
	require.Equal(t, goroutines-1, replays)

	last, ok := validator.LastConsumed()
	require.True(t, ok)
	require.Equal(t, uint64(1), last)
}
