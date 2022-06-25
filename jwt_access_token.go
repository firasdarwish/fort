/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

type jwtAccessToken struct {
	ID          string `json:"jti"`
	DisplayName string `json:"name"`
	UserId      any    `json:"uid"`

	UserStateHash string `json:"x_ush"`

	Issuer   string `json:"iss"`
	Audience string `json:"aud"`

	Scope string   `json:"scope"`
	Roles []string `json:"roles"`

	AdditionalInfo map[string]any `json:"additional_info"`

	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

func (j jwtAccessToken) Valid() error {
	return nil
}
