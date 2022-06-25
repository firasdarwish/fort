/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	"github.com/golang-jwt/jwt"
	"time"
)

type loginResult struct {
	g                 *guard
	auth              *Auth
	user              map[string]any
	userInfo          *UserInfo
	plainRefreshToken *string
}

func (l *loginResult) User() map[string]any {
	return l.user
}

func (l *loginResult) UserInfo() *UserInfo {
	return l.userInfo
}

func (l *loginResult) JWT(additionalInfo map[string]any) (*JwtResult, error) {
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

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(l.g.config.LoginConfig.JWTConfig.SecretKey)
	if err != nil {
		return nil, err
	}

	jwtRes := JwtResult{
		AccessToken:           tokenString,
		RefreshToken:          l.plainRefreshToken,
		AccessTokenExpiresAt:  atExp,
		RefreshTokenExpiresAt: &l.auth.ExpiresAt,
	}

	return &jwtRes, nil
}

type LoginResult interface {
	User() map[string]any
	UserInfo() *UserInfo

	JWT(additionalInfo map[string]any) (*JwtResult, error)
}
