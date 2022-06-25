/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSED UNDER APACHE 2.0
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	"encoding/json"
	"github.com/pquerna/otp/totp"
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
		totpResp.IPAddress != ip {
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

	validTotp := totp.Validate(code, ui.TOTPSecretKey)
	if !validTotp {
		return nil, IncorrectTOTPCode
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
