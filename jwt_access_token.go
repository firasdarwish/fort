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
	"time"
)

type jwtAccessToken struct {
	ID          string `json:"jti"`
	DisplayName string `json:"name,omitempty"`
	UserId      any    `json:"uid"`

	UserStateHash string `json:"x_ush"`

	Issuer   string `json:"iss,omitempty"`
	Audience string `json:"aud,omitempty"`

	Scope string   `json:"scope,omitempty"`
	Roles []string `json:"roles,omitempty"`

	AdditionalInfo map[string]any `json:"additional_info,omitempty"`

	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

func (j jwtAccessToken) Valid() error {
	return nil
}

func (g *guard) toAccessToken(accessToken string) (*jwtAccessToken, error) {
	jwt.TimeFunc = func() time.Time {
		return time.Unix(0, 0)
	}

	t, err := jwt.ParseWithClaims(accessToken, &jwtAccessToken{}, func(token *jwt.Token) (interface{}, error) {
		return g.config.LoginConfig.JWTConfig.SecretKey, nil
	})
	jwt.TimeFunc = time.Now

	if err != nil {
		return nil, err
	}

	// check signing algo && validity
	if t.Method != g.config.LoginConfig.JWTConfig.Algorithm ||
		!t.Valid {
		return nil, InvalidAccessToken
	}

	claims, ok := t.Claims.(*jwtAccessToken)
	if !ok {
		return nil, InvalidAccessToken
	}

	return claims, nil
}
