/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

type guard struct {
	name   string
	config *GuardConfig
}

type Guard interface {
	Login(userAgent *string, ip *string, props map[string]any) (LoginResult, error)
}
