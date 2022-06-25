/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

type PasswordsHasherComparer interface {
	Hash(plainPassword string) (string, error)
	Compare(plainPassword, hash string) bool
}
