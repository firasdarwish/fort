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
