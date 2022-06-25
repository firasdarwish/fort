/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSED UNDER APACHE 2.0
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

type loginResult struct {
	g                 *guard
	auth              *Auth
	user              map[string]any
	userInfo          *UserInfo
	totpIntermResp    *totpIntermediateResponse
	plainRefreshToken *string
}

func (l *loginResult) User() map[string]any {
	return l.user
}

func (l *loginResult) UserInfo() *UserInfo {
	return l.userInfo
}

type LoginResult interface {
	User() map[string]any
	UserInfo() *UserInfo

	TOTPToken() (*string, error)

	JWT(additionalInfo map[string]any) (*JwtResult, error)
}
