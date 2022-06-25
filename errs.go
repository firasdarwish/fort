/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSED UNDER APACHE 2.0
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import "errors"

var (
	GuardNameAlreadyExists = errors.New("guard already exists")
	GuardNotFound          = errors.New("guard not found")
	InvalidCredentials     = errors.New("invalid credentials")
	InvalidPassword        = errors.New("invalid password")
	HandlerNotAllowed      = errors.New("handler not allowed")
	EmptyHandler           = errors.New("handler has no value")

	Collision = errors.New("collision, too many records")

	IncorrectCredentials = errors.New("incorrect credentials")

	InvalidUserId = errors.New("invalid user id")

	MustValidateTOTP = errors.New("user must validate TOTP first")

	InvalidTOTPLogin  = errors.New("invalid TOTP login request")
	IncorrectTOTPCode = errors.New("incorrect TOTP code")

	TOTPLoginDisabled = errors.New("TOTP login is disabled")
)
