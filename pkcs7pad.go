// Package pkcs7pad implements PKCS#7 padding, as defined in RFC 5652.
//
// https://tools.ietf.org/html/rfc5652#section-6.3
package pkcs7pad

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
)

var errPKCS7Padding = errors.New("pkcs7pad: bad padding")

// Pad appends PKCS#7 padding to the given buffer such that the resulting slice
// of bytes has a length divisible by the given size. If you are using this
// function to pad a plaintext before encrypting it with a block cipher, the
// size should be equal to the block size of the cipher (e.g., aes.BlockSize).
func Pad(buf []byte, size int) []byte {
	if size < 1 || size > 255 {
		panic(fmt.Sprintf("pkcs7pad: inappropriate block size %d", size))
	}
	i := size - (len(buf) % size)
	return append(buf, bytes.Repeat([]byte{byte(i)}, i)...)
}

// Unpad returns a subslice of the input buffer with trailing PKCS#7 padding
// removed. It checks the correctness of the padding bytes in constant time, and
// returns an error if the padding bytes are malformed.
func Unpad(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, errPKCS7Padding
	}

	// Here be dragons. We're attempting to check the padding in constant
	// time. The only piece of information here which is public is len(buf).
	// This code is modeled loosely after tls1_cbc_remove_padding from
	// OpenSSL.
	padLen := buf[len(buf)-1]
	toCheck := 255
	good := 1
	if toCheck > len(buf) {
		toCheck = len(buf)
	}
	for i := 0; i < toCheck; i++ {
		b := buf[len(buf)-1-i]

		outOfRange := subtle.ConstantTimeLessOrEq(int(padLen), i)
		equal := subtle.ConstantTimeByteEq(padLen, b)
		good &= subtle.ConstantTimeSelect(outOfRange, 1, equal)
	}

	good &= subtle.ConstantTimeLessOrEq(1, int(padLen))
	good &= subtle.ConstantTimeLessOrEq(int(padLen), len(buf))

	if good != 1 {
		return nil, errPKCS7Padding
	}

	return buf[:len(buf)-int(padLen)], nil
}
