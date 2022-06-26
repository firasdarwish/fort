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
	"github.com/pquerna/otp/totp"
	"time"
)

const SKIP_TOTP_LOGIN = 654 // 0

func (g *guard) LoginTOTP(userAgent *string, ip *string, token string, code string) (LoginResult, error) {
	if g.config.LoginConfig.TOTP == false {
		return nil, TOTPLoginDisabled
	}

	dec, err := aesDecrypt(g.config.AESSecretKey, token)
	if err != nil {
		return nil, err
	}

	var totpResp totpIntermediateResponse
	err = json.Unmarshal([]byte(dec), &totpResp)

	if totpResp.UserAgent != userAgent ||
		totpResp.IPAddress != ip ||
		time.Now().Sub(totpResp.CreatedAt) >= g.config.LoginConfig.TOTPIntermediateResponseTTL {
		return nil, InvalidTOTPLogin
	}

	gState, err := g.state()
	if err != nil {
		return nil, err
	}

	if gState != totpResp.GuardStateHash {
		return nil, InvalidTOTPLogin
	}

	user, err := g.getUserByProps(totpResp.Props)
	if err != nil {
		return nil, err
	}

	ui := g.config.GetUserInfo(user)

	userStateHash, err := ui.userState(g.config.AESSecretKey)
	if err != nil {
		return nil, err
	}

	if userStateHash != totpResp.UserStateHash {
		return nil, InvalidTOTPLogin
	}

	if g.config.TOTPConfig == nil {
		validTotp := totp.Validate(code, ui.TOTPSecretKey)
		if !validTotp {
			return nil, IncorrectTOTPCode
		}
	} else {
		validTotp, err := totp.ValidateCustom(code, ui.TOTPSecretKey, g.config.TOTPConfig.Now(), totp.ValidateOpts{
			Period:    g.config.TOTPConfig.Period,
			Skew:      g.config.TOTPConfig.Skew,
			Digits:    g.config.TOTPConfig.Digits,
			Algorithm: g.config.TOTPConfig.Algorithm,
		})

		if err != nil {
			return nil, err
		}
		if !validTotp {
			return nil, IncorrectTOTPCode
		}
	}

	totpResp.Props["password"] = totpResp.Password

	return g.Login(userAgent, ip, totpResp.Props, SKIP_TOTP_LOGIN)
}

func skipTOTP(params []int) bool {
	if params != nil && len(params) > 0 && params[0] == SKIP_TOTP_LOGIN {
		return true
	}

	return false
}
