/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSED UNDER APACHE 2.0
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	"encoding/json"
	errors2 "github.com/pkg/errors"
	"time"
)

type totpIntermediateResponse struct {
	GuardStateHash string         `json:"gsh"`
	UserStateHash  string         `json:"ush"`
	Props          map[string]any `json:"p"`
	Password       string         `json:"pass"`
	IPAddress      *string        `json:"ip"`
	UserAgent      *string        `json:"ua"`
	CreatedAt      time.Time      `json:"at"`
}

func (l *loginResult) TOTPToken() (*string, error) {
	if l.g.mustValidateTotp(l.userInfo) == false {
		return nil, nil
	}

	b, err := json.Marshal(l.totpIntermResp)
	if err != nil {
		return nil, errors2.Wrap(err, "couldnt generate TOTP token")
	}

	enc, err := aesEncrypt(l.g.config.AESSecretKey, string(b))
	if err != nil {
		return nil, errors2.Wrap(err, "couldnt generate TOTP token")
	}

	return &enc, nil
}
