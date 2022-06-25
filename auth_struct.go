/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
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
