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

package internal

import (
	"io"

	"github.com/pquerna/otp"
)

// PrepareSecret implements the shared secret policy for hotp.Generate and
// totp.Generate. A caller supplied secret is used as-is but must meet the
// minimum strength; otherwise a secret of secretSize (defaulting to
// otp.DefaultSecretSize) bytes is read from rand. A short read of rand is an
// error: io.ReadFull returns ErrUnexpectedEOF rather than returning a
// partially randomized secret.
func PrepareSecret(secret []byte, secretSize uint, rand io.Reader) ([]byte, error) {
	if len(secret) != 0 {
		if len(secret) < otp.MinSecretSize {
			return nil, otp.ErrWeakSecretSize
		}
		return secret, nil
	}

	if secretSize == 0 {
		secretSize = otp.DefaultSecretSize
	}

	if secretSize < otp.MinSecretSize {
		return nil, otp.ErrWeakSecretSize
	}

	generated := make([]byte, secretSize)
	if _, err := io.ReadFull(rand, generated); err != nil {
		return nil, err
	}

	return generated, nil
}

// ValidateEncoding enforces the shared encoder/digits policy used when keys
// are generated and exported into otpauth URIs. The default numeric encoder
// accepts six or eight digits per RFC 4226 / RFC 6238; the Steam encoder
// uses five digits over otp.SteamChars. Unknown combinations fail closed.
func ValidateEncoding(encoder otp.Encoder, digits otp.Digits) error {
	switch encoder {
	case otp.EncoderDefault:
		if digits != otp.DigitsSix && digits != otp.DigitsEight {
			return otp.ErrInvalidDigits
		}
	case otp.EncoderSteam:
		if digits != otp.DigitsFive {
			return otp.ErrInvalidDigits
		}
	default:
		return otp.ErrUnsupportedEncoder
	}
	return nil
}
