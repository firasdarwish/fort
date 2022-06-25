/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import "golang.org/x/crypto/bcrypt"

func bcryptHash(plainText string) (string, error) {
	password, err := bcrypt.GenerateFromPassword([]byte(plainText), 10)
	if err != nil {
		return "", err
	}

	return string(password), nil
}

func bcryptCompare(plainText, hashedText string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedText), []byte(plainText))
	if err != nil {
		return false
	}

	return true
}
