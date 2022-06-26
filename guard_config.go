/*
 * Copyright 2022 Firas M. Darwish <firas@dev.sy>
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
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
	TOTPConfig  *TOTPConfig
}

type LoginConfig struct {
	AllowedHandlers         []string // username, email, mobile ...
	PasswordsHasherComparer PasswordsHasherComparer

	TOTP                        bool
	TOTPIntermediateResponseTTL time.Duration

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
