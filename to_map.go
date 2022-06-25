/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSED UNDER APACHE 2.0
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import (
	"encoding/json"
	errors2 "github.com/pkg/errors"
)

func toMap(doc any) (map[string]any, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, errors2.Wrap(err, "couldnt convert to map")
	}

	var m map[string]any
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, errors2.Wrap(err, "couldnt convert to map")
	}

	return m, nil
}
