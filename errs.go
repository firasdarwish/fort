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
