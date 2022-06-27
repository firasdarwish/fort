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

func (g *guard) Login(userAgent *string, ip *string, props map[string]any, params ...int) (LoginResult, error) {
	validProps, err := g.config.LoginConfig.validateProps(props)
	if !validProps || err != nil {
		return nil, err
	}

	plainPassword := props["password"].(string)

	delete(props, "password")

	user, err := g.getUserByProps(props)
	if err != nil {
		return nil, err
	}

	authedUser := g.config.GetUserInfo(user)

	okPassword := g.config.LoginConfig.PasswordsHasherComparer.Compare(plainPassword, authedUser.Password)
	if !okPassword {
		return nil, IncorrectCredentials
	}

	userId := authedUser.ID
	if userId == nil {
		return nil, InvalidUserId
	}

	userStateHash, err := authedUser.userState(g)
	if err != nil {
		return nil, err
	}

	if !skipTOTP(params) && g.mustValidateTotp(&authedUser) {
		gState, err := g.state()
		if err != nil {
			return nil, err
		}

		return &loginResult{
			g:        g,
			auth:     nil,
			user:     user,
			userInfo: &authedUser,
			totpIntermResp: &totpIntermediateResponse{
				GuardStateHash: gState,
				UserStateHash:  userStateHash,
				Props:          props,
				Password:       plainPassword,
				IPAddress:      ip,
				UserAgent:      userAgent,
				CreatedAt:      time.Now(),
			},
			plainRefreshToken: nil,
		}, nil
	}

	uniqueToken, err := generateRandomString(32, allCharset)
	if err != nil {
		return nil, errors2.Wrap(err, "couldnt generate random unique token")
	}

	var refreshToken, plainRefreshToken *string
	if g.config.LoginConfig.Refreshable {
		plainRefreshTokenStr, err := generateRandomString(64, allCharset)
		if err != nil {
			return nil, errors2.Wrap(err, "couldnt generate random refresh token")
		}

		hashedRefreshToken, err := bcryptHash(plainRefreshTokenStr)
		if err != nil {
			return nil, errors2.Wrap(err, "couldnt bcrypt hash refresh token")
		}

		refreshToken = &hashedRefreshToken
		plainRefreshToken = &plainRefreshTokenStr
	}

	a := Auth{
		Guard:              g.name,
		UserTable:          g.config.UsersTable,
		UserId:             userId,
		UserStateHash:      userStateHash,
		UniqueToken:        uniqueToken,
		HashedRefreshToken: refreshToken,
		UserAgent:          userAgent,
		IPAddress:          ip,
		ExpiresAt:          time.Now().Add(g.config.LoginConfig.ExpiresAfter),
		CreatedAt:          time.Now(),
		UpdatedAt:          nil,
		RevokedAt:          nil,
		LastActivityAt:     time.Now(),
	}

	return &loginResult{
		g:                 g,
		auth:              &a,
		user:              user,
		userInfo:          &authedUser,
		plainRefreshToken: plainRefreshToken,
	}, nil
}
