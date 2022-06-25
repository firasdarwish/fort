/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	"crypto/rand"
	"math/big"
)

const allCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-:.@()+,=;$!*'%"

// generateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateRandomString(n int, charset string) (string, error) {
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		ret[i] = charset[num.Int64()]
	}

	return string(ret), nil
}
