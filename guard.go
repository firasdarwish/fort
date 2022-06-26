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

	Refresh(userAgent *string, ip *string, accessToken, refreshToken string) (LoginResult, error)
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
