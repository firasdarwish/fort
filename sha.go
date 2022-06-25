/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	"crypto/sha256"
	"fmt"
)

func hashSha256(payload string) string {
	c := sha256.New()
	c.Write([]byte(payload))

	t := fmt.Sprintf("%x", c.Sum(nil))
	return t
}
