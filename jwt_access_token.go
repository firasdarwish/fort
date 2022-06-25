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
