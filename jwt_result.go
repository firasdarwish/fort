/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSED UNDER APACHE 2.0
 * LICENSE IS INCLUDED IN PROJECT FILES.
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
