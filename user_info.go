/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSED UNDER APACHE 2.0
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	errors2 "github.com/pkg/errors"
	"time"
)

type UserInfo struct {
	ID          any
	DisplayName string
	Email       string
	Mobile      string
	Password    string
	Scope       string
	Roles       []string

	TOTPSecretKey     string
	TOTPRecoveryCodes []string
	TOTPConfirmedAt   *time.Time
}

func (g *guard) mustValidateTotp(ui *UserInfo) bool {
	if g.config.LoginConfig.TOTP && ui.TOTPSecretKey != "" && ui.TOTPConfirmedAt != nil {
		return true
	}

	return false
}

func (g *guard) getUserByProps(props map[string]any) (map[string]any, error) {
	users, err := g.config.UserStore.GetByProps(g.config.UsersTable, props, 2, false)
	if err != nil {
		return nil, err
	}

	if users == nil || len(users) == 0 {
		return nil, IncorrectCredentials
	}

	if len(users) > 1 {
		return nil, errors2.Wrapf(Collision, "users table")
	}

	return users[0], nil
}
