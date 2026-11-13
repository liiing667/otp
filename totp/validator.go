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
	"crypto/subtle"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// Validator is a concurrency safe, stateful TOTP verifier.
//
// The stateless Validate and ValidateCustom functions accept a passcode for
// every time-step inside the skew window, so the same passcode can be
// presented repeatedly until the window rotates. A Validator remembers the
// last time-step (HOTP counter) it consumed, so a passcode is accepted at
// most once even while it remains inside the skew window.
//
// A Validator must be created with NewValidator and is safe for concurrent
// use by multiple goroutines.
type Validator struct {
	mu       sync.Mutex
	secret   string
	opts     ValidateOpts
	used     bool
	lastUsed uint64
}

// NewValidator creates a Validator for secret. Period, Skew, Digits and
// Algorithm default the same way GenerateCode and Validate do.
func NewValidator(secret string, opts ValidateOpts) *Validator {
	if opts.Period == 0 {
		opts.Period = 30
	}
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	return &Validator{
		secret: secret,
		opts:   opts,
	}
}

// LastConsumed returns the HOTP counter (time-step) of the most recently
// consumed passcode. The boolean result is false until the first successful
// validation.
func (v *Validator) LastConsumed() (uint64, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lastUsed, v.used
}

// Validate checks passcode against the time-steps around t within the skew
// window.
//
// On success it returns true and the matched time-step counter, which is
// recorded so the same passcode cannot be consumed again. A passcode for an
// already consumed time-step returns otp.ErrCodeReplayed, and any other
// rejected passcode returns false with a nil error. In every failure case the
// Validator's state is left untouched.
func (v *Validator) Validate(passcode string, t time.Time) (valid bool, matchedCounter uint64, err error) {
	passcode = strings.TrimSpace(passcode)

	if len(passcode) != v.opts.Digits.Length() {
		return false, 0, otp.ErrValidateInputInvalidLength
	}

	current := uint64(math.Floor(float64(t.Unix()) / float64(v.opts.Period)))

	v.mu.Lock()
	defer v.mu.Unlock()

	hotpOpts := hotp.ValidateOpts{
		Digits:    v.opts.Digits,
		Algorithm: v.opts.Algorithm,
		Encoder:   v.opts.Encoder,
	}

	counters := []uint64{current}
	for offset := uint(1); offset <= v.opts.Skew; offset++ {
		counters = append(counters, uint64(int64(current)+int64(offset)))
		counters = append(counters, uint64(int64(current)-int64(offset)))
	}

	for _, counter := range counters {
		otpstr, genErr := hotp.GenerateCodeCustom(v.secret, counter, hotpOpts)
		if genErr != nil {
			return false, 0, genErr
		}

		if subtle.ConstantTimeCompare([]byte(otpstr), []byte(passcode)) != 1 {
			continue
		}

		if v.used && counter == v.lastUsed {
			return false, v.lastUsed, otp.ErrCodeReplayed
		}

		v.lastUsed = counter
		v.used = true
		return true, counter, nil
	}

	return false, 0, nil
}

// ValidateNow is Validate with the current UTC time.
func (v *Validator) ValidateNow(passcode string) (bool, uint64, error) {
	return v.Validate(passcode, time.Now().UTC())
}
