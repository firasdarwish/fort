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

type JwtResult struct {
	AccessToken  string
	RefreshToken *string

	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt *time.Time
}

func (l *loginResult) JWT(additionalInfo map[string]any) (*JwtResult, error) {
	if l.g.mustValidateTotp(l.userInfo) && l.totpIntermResp != nil {
		return nil, MustValidateTOTP
	}

	atExp := time.Now().Add(time.Minute * time.Duration(l.g.config.LoginConfig.JWTConfig.AccessTokenTTLMins))
	at := jwtAccessToken{
		ID:             l.auth.UniqueToken,
		DisplayName:    l.userInfo.DisplayName,
		UserId:         l.userInfo.ID,
		UserStateHash:  l.auth.UserStateHash,
		Issuer:         l.g.config.LoginConfig.JWTConfig.Issuer,
		Audience:       l.g.config.LoginConfig.JWTConfig.Audience,
		Scope:          l.userInfo.Scope,
		Roles:          l.userInfo.Roles,
		AdditionalInfo: additionalInfo,
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      atExp.Unix(),
	}

	token := jwt.NewWithClaims(l.g.config.LoginConfig.JWTConfig.Algorithm, at)

	tokenString, err := token.SignedString(l.g.config.LoginConfig.JWTConfig.SecretKey)
	if err != nil {
		return nil, err
	}

	return &JwtResult{
		AccessToken:           tokenString,
		RefreshToken:          l.plainRefreshToken,
		AccessTokenExpiresAt:  atExp,
		RefreshTokenExpiresAt: &l.auth.ExpiresAt,
	}, nil
}
