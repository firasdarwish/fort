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
	"encoding/json"
	"time"
)

type Auth struct {
	Guard     string `json:"guard"`
	UserTable string `json:"user_table"`
	UserId    any    `json:"user_id"`

	UserStateHash string `json:"user_state_hash"`

	UniqueToken        string  `json:"unique_token"`         // plain, acts like primary key
	HashedRefreshToken *string `json:"hashed_refresh_token"` // one-way hash, null = un-refreshable

	UserAgent *string
	IPAddress *string

	ExpiresAt time.Time

	CreatedAt      time.Time
	UpdatedAt      *time.Time
	RevokedAt      *time.Time
	LastActivityAt time.Time // at init, = CreatedAt
}

func (g *guard) insertAuth(a *Auth) error {
	m, err := toMap(a)
	if err != nil {
		return err
	}

	err = g.config.AuthStore.Insert(g.config.AuthTable, m)
	if err != nil {
		return err
	}

	return nil
}

func authFromMap(m map[string]any) (Auth, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return Auth{}, err
	}

	var a Auth
	err = json.Unmarshal(b, &a)
	if err != nil {
		return Auth{}, err
	}

	return a, nil
}
