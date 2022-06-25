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
