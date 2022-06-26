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
	errors2 "github.com/pkg/errors"
	"time"
)

func (g *guard) Refresh(userAgent *string, ip *string, accessToken, refreshToken string) (LoginResult, error) {
	if !g.config.LoginConfig.Refreshable {
		return nil, NotRefreshable
	}

	claims, err := g.toAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	user, err := g.getUserByProps(map[string]any{
		g.config.UserIdKey: claims.UserId,
	})
	if err != nil {
		return nil, err
	}

	authRows, err := g.config.AuthStore.GetByProps(g.config.AuthTable, map[string]any{
		"unique_token": claims.ID,
	}, 2, false)
	if err != nil {
		return nil, err
	}

	if authRows == nil || len(authRows) != 1 {
		return nil, InvalidAccessToken
	}

	authRow, err := authFromMap(authRows[0])
	if err != nil {
		return nil, err
	}

	old_auth_row := authRow

	if authRow.HashedRefreshToken == nil {
		return nil, InvalidAccessToken
	}

	validRfTok := bcryptCompare(refreshToken, *authRow.HashedRefreshToken)
	if !validRfTok {
		return nil, InvalidAccessToken
	}

	if authRow.RevokedAt != nil {
		return nil, RefreshTokenRevoked
	}

	if time.Now().After(authRow.ExpiresAt) {
		return nil, RefreshTokenExpired
	}

	ui := g.config.GetUserInfo(user)
	userState, err := ui.userState(g)
	if err != nil {
		return nil, err
	}

	if userState != claims.UserStateHash ||
		userState != authRow.UserStateHash {
		return nil, InvalidAccessToken
	}

	uniqueToken, err := generateRandomString(32, allCharset)
	if err != nil {
		return nil, errors2.Wrap(err, "couldnt generate random unique token")
	}

	var plainRefreshToken *string
	plainRefreshTokenStr, err := generateRandomString(64, allCharset)
	if err != nil {
		return nil, errors2.Wrap(err, "couldnt generate random refresh token")
	}

	hashedRefreshToken, err := bcryptHash(plainRefreshTokenStr)
	if err != nil {
		return nil, errors2.Wrap(err, "couldnt bcrypt hash refresh token")
	}

	plainRefreshToken = &plainRefreshTokenStr

	now := time.Now()
	authRow.UniqueToken = uniqueToken
	authRow.HashedRefreshToken = &hashedRefreshToken
	authRow.UserAgent = userAgent
	authRow.IPAddress = ip
	authRow.UpdatedAt = &now
	authRow.LastActivityAt = now
	authRow.ExpiresAt = now.Add(g.config.LoginConfig.ExpiresAfter)

	return &loginResult{
		old_auth:          &old_auth_row,
		g:                 g,
		auth:              &authRow,
		user:              user,
		userInfo:          &ui,
		totpIntermResp:    nil,
		plainRefreshToken: plainRefreshToken,
	}, nil
}
