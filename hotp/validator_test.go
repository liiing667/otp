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
	"encoding/base32"
	"sync"
	"testing"

	"github.com/pquerna/otp"
	"github.com/stretchr/testify/require"
)

func validatorSecret() string {
	return base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
}

// The RFC 4226 appendix-D matrix must validate in order, and each success
// must report the counter it consumed.
func TestValidatorRFCSequence(t *testing.T) {
	validator := NewValidator(validatorSecret(), 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	for _, tx := range rfcMatrixTCs {
		valid, consumed, err := validator.Validate(tx.TOTP)
		require.NoError(t, err)
		require.True(t, valid, "counter %v passcode %v rejected", tx.Counter, tx.TOTP)
		require.Equal(t, tx.Counter, consumed)
		require.Equal(t, tx.Counter+1, validator.Counter())
	}
}

// Replaying a consumed passcode must fail and leave the counter untouched.
func TestValidatorReplayDoesNotAdvance(t *testing.T) {
	validator := NewValidator(validatorSecret(), 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	valid, consumed, err := validator.Validate(rfcMatrixTCs[0].TOTP)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(0), consumed)

	valid, consumed, err = validator.Validate(rfcMatrixTCs[0].TOTP)
	require.NoError(t, err)
	require.False(t, valid)
	require.Equal(t, uint64(0), consumed)
	require.Equal(t, uint64(1), validator.Counter(), "replay must not move the counter")
}

// A look-ahead window tolerates skipped counters but jumps past every
// counter up to and including the matched one.
func TestValidatorWindowSkips(t *testing.T) {
	validator := NewValidator(validatorSecret(), 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	validator.SetWindow(2)
	require.Equal(t, uint64(2), validator.Window())

	valid, consumed, err := validator.Validate(rfcMatrixTCs[2].TOTP)
	require.NoError(t, err)
	require.True(t, valid)
	require.Equal(t, uint64(2), consumed)
	require.Equal(t, uint64(3), validator.Counter())

	// Counters 0-2 are now consumed and must all replay as failures.
	for _, tx := range rfcMatrixTCs[:3] {
		valid, _, err = validator.Validate(tx.TOTP)
		require.NoError(t, err)
		require.False(t, valid)
	}
	require.Equal(t, uint64(3), validator.Counter())
}

func TestValidatorRejectsOutsideWindow(t *testing.T) {
	validator := NewValidator(validatorSecret(), 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	valid, consumed, err := validator.Validate(rfcMatrixTCs[3].TOTP)
	require.NoError(t, err)
	require.False(t, valid)
	require.Equal(t, uint64(0), consumed)
	require.Equal(t, uint64(0), validator.Counter(), "failure must not move the counter")
}

func TestValidatorInvalidLength(t *testing.T) {
	validator := NewValidator(validatorSecret(), 0, ValidateOpts{})

	valid, _, err := validator.Validate("12345")
	require.Equal(t, otp.ErrValidateInputInvalidLength, err)
	require.False(t, valid)
	require.Equal(t, uint64(0), validator.Counter())
}

// Under contention exactly one goroutine may consume a counter.
func TestValidatorConcurrentConsumption(t *testing.T) {
	validator := NewValidator(validatorSecret(), 0, ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	const goroutines = 64
	var wg sync.WaitGroup
	results := make(chan bool, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			valid, _, err := validator.Validate(rfcMatrixTCs[0].TOTP)
			require.NoError(t, err)
			results <- valid
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	for valid := range results {
		if valid {
			successes++
		}
	}

	require.Equal(t, 1, successes)
	require.Equal(t, uint64(1), validator.Counter())
}
