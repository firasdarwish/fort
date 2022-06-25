/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSED UNDER APACHE 2.0
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	"fmt"
	errors2 "github.com/pkg/errors"
)

type guard struct {
	name   string
	config *GuardConfig
}

type Guard interface {
	Login(userAgent *string, ip *string, props map[string]any, params ...int) (LoginResult, error)
	LoginTOTP(userAgent *string, ip *string, token string, code string) (LoginResult, error)
}

func (g *guard) state() (string, error) {
	s := fmt.Sprintf("%v|%v|%v", g.name, g.config.UsersTable, g.config.AuthTable)
	hash := hashSha256(s)
	enc, err := aesDecrypt(g.config.AESSecretKey, hash)
	if err != nil {
		return "", errors2.Wrap(err, "couldnt encrypt guard state")
	}

	return enc, nil
}
