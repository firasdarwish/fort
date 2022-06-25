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
	"time"
)

type Auth struct {
	Guard     string
	UserTable string
	UserId    any

	UserStateHash string

	UniqueToken        string  // plain, acts like primary key
	HashedRefreshToken *string // one-way hash, null = un-refreshable

	UserAgent *string
	IPAddress *string

	ExpiresAt time.Time

	CreatedAt      time.Time
	UpdatedAt      *time.Time
	RevokedAt      *time.Time
	LastActivityAt time.Time // at init, = CreatedAt
}

func (ui *UserInfo) userState(aesSecretKey []byte) (string, error) {
	s := fmt.Sprintf("%v|%v|%v|%v|%v", ui.ID, ui.Password, ui.TOTPSecretKey, ui.Email, ui.Mobile)
	hash := hashSha256(s)
	enc, err := aesEncrypt(aesSecretKey, hash)
	if err != nil {
		return "", errors2.Wrap(err, "couldnt encrypt user state")
	}

	return enc, nil
}

func (ui *UserInfo) validateUserState(aesSecretKey []byte, encryptedHash string) (bool, error) {
	s, err := ui.userState(aesSecretKey)
	if err != nil {
		return false, err
	}

	return encryptedHash == s, nil
}
