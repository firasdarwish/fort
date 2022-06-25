/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import "time"

type JwtResult struct {
	AccessToken  string
	RefreshToken *string

	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt *time.Time
}
