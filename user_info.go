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

type UserInfo struct {
	ID          any
	DisplayName string
	Email       string
	Mobile      string
	Password    string
	Scope       string
	Roles       []string

	TOTPSecretKey string
	TOTPActive    bool
}

func (g *guard) mustValidateTotp(ui *UserInfo) bool {
	if g.config.LoginConfig.TOTP && ui.TOTPSecretKey != "" && ui.TOTPActive {
		return true
	}

	return false
}

func (g *guard) getUserByProps(props map[string]any) (map[string]any, error) {
	users, err := g.config.UserStore.GetByProps(g.config.UsersTable, props, 2, false)
	if err != nil {
		return nil, err
	}

	if users == nil || len(users) == 0 {
		return nil, IncorrectCredentials
	}

	if len(users) > 1 {
		return nil, errors2.Wrapf(Collision, "users table")
	}

	return users[0], nil
}

func (ui *UserInfo) userState(g *guard) (string, error) {
	gState, err := g.state()
	if err != nil {
		return "", err
	}

	s := fmt.Sprintf("%v|%v|%v|%v|%v|%v", ui.ID, ui.Password, ui.TOTPSecretKey, ui.Email, ui.Mobile, gState)
	hash := hashSha256(s)
	enc, err := aesEncrypt(g.config.AESSecretKey, hash)
	if err != nil {
		return "", errors2.Wrap(err, "couldnt encrypt user state")
	}

	return enc, nil
}

func (ui *UserInfo) validateUserState(encryptedHash string, g *guard) (bool, error) {
	s, err := ui.userState(g)
	if err != nil {
		return false, err
	}

	return encryptedHash == s, nil
}
