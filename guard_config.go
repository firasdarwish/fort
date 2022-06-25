/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSED UNDER APACHE 2.0
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"strings"
	"time"
)

type GuardConfig struct {
	UserStore   Store
	UsersTable  string // users, admins, mods ...
	AuthTable   string
	GetUserInfo func(map[string]any) UserInfo

	AESSecretKey []byte

	LoginConfig *LoginConfig
}

type LoginConfig struct {
	AllowedHandlers         []string // username, email, mobile ...
	PasswordsHasherComparer PasswordsHasherComparer

	TOTP                            bool
	TOTPIntermediateResponseTTLMins int

	ExpiresAfter time.Duration
	Refreshable  bool

	JWTConfig *JWTConfig
}

type JWTConfig struct {
	SecretKey          []byte
	AccessTokenTTLMins int
	Audience           string
	Issuer             string
	Algorithm          jwt.SigningMethod
}

func (lc *LoginConfig) validateProps(props map[string]any) (bool, error) {
	if props == nil || len(props) < 2 {
		return false, InvalidCredentials
	}

	plainPassword, exists := props["password"]
	if !exists {
		return false, InvalidPassword
	}

	strPlainPassword, ok := plainPassword.(string)
	if !ok || strings.TrimSpace(strPlainPassword) == "" {
		return false, InvalidPassword
	}

	for k, v := range props {
		if v == nil || v == "" {
			return false, errors.Wrap(EmptyHandler, k)
		}

		if k != "password" {
			isAllowed := false

			for _, allowedProp := range lc.AllowedHandlers {
				if k == allowedProp {
					isAllowed = true
					break
				}
			}

			if !isAllowed {
				return false, errors.Wrap(HandlerNotAllowed, k)
			}
		}
	}

	return true, nil
}
