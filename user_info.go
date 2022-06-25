/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import "time"

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
