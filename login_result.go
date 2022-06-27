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

type loginResult struct {
	g                 *guard
	auth              *Auth
	oldAuth           *Auth
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
