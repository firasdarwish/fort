/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	errors2 "github.com/pkg/errors"
	"time"
)

func (g *guard) Login(userAgent *string, ip *string, props map[string]any) (LoginResult, error) {
	validProps, err := g.config.LoginConfig.validateProps(props)
	if !validProps || err != nil {
		return nil, err
	}

	plainPassword := props["password"].(string)

	delete(props, "password")

	users, err := g.config.UserStore.GetByProps(g.config.UsersTable, props, 2, false)
	if err != nil {
		return nil, errors2.Wrap(err, "couldnt login")
	}

	if users == nil || len(users) == 0 {
		return nil, IncorrectCredentials
	}

	if len(users) > 1 {
		return nil, errors2.Wrapf(Collision, "users table")
	}

	authedUser := g.config.GetUserInfo(users[0])

	okPassword := g.config.LoginConfig.PasswordsHasherComparer.Compare(plainPassword, authedUser.Password)
	if !okPassword {
		return nil, IncorrectCredentials
	}

	userId := authedUser.ID
	if userId == nil {
		return nil, InvalidUserId
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

	userStateHash, err := authedUser.userState(g.config.AESSecretKey)
	if err != nil {
		return nil, err
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
		auth:              &a,
		user:              users[0],
		userInfo:          &authedUser,
		plainRefreshToken: plainRefreshToken,
	}, nil
}
