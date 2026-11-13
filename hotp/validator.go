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
	"crypto/subtle"
	"strings"
	"sync"

	"github.com/pquerna/otp"
)

// Validator is a concurrency safe, stateful HOTP verifier.
//
// The stateless Validate and ValidateCustom functions only report whether a
// passcode matches a counter; they cannot tell whether that passcode was
// already used. A Validator owns the moving counter itself, so a successful
// validation atomically consumes the matching counter and the same passcode
// can never be accepted twice.
//
// A Validator must be created with NewValidator and is safe for concurrent
// use by multiple goroutines.
type Validator struct {
	mu      sync.Mutex
	secret  string
	opts    ValidateOpts
	counter uint64
	window  uint64
}

// NewValidator creates a Validator for secret. counter is the next counter
// expected from the client (the server's current HOTP counter), and window is
// how many counters ahead of it may be accepted to tolerate client-side
// drift. A window of zero enforces strict, in-order validation.
func NewValidator(secret string, counter uint64, opts ValidateOpts) *Validator {
	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}
	return &Validator{
		secret:  secret,
		opts:    opts,
		counter: counter,
	}
}

// Counter returns the next counter the Validator expects. After a successful
// validation this is one greater than the counter that was consumed.
func (v *Validator) Counter() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.counter
}

// SetWindow sets how many counters ahead of the expected counter may be
// accepted. It is safe to call concurrently with Validate.
func (v *Validator) SetWindow(window uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.window = window
}

// Window returns the currently configured look-ahead window.
func (v *Validator) Window() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.window
}

// Validate checks passcode against the counters in the look-ahead window and,
// on a match, atomically advances the internal counter past the matched one.
//
// On success it returns true and the counter that was consumed. A rejected
// passcode, including any attempt to replay an already consumed counter,
// returns false without modifying the Validator's state.
func (v *Validator) Validate(passcode string) (valid bool, consumedCounter uint64, err error) {
	passcode = strings.TrimSpace(passcode)

	if len(passcode) != v.opts.Digits.Length() {
		return false, 0, otp.ErrValidateInputInvalidLength
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	last := v.counter + v.window
	for counter := v.counter; ; counter++ {
		otpstr, genErr := GenerateCodeCustom(v.secret, counter, v.opts)
		if genErr != nil {
			return false, 0, genErr
		}

		if subtle.ConstantTimeCompare([]byte(otpstr), []byte(passcode)) == 1 {
			consumedCounter = counter
			v.counter = counter + 1
			return true, consumedCounter, nil
		}

		if counter == last {
			return false, 0, nil
		}
	}
}
