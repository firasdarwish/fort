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

func (f *fort) NewGuard(name string, config *GuardConfig) (Guard, error) {
	_, err := f.GetGuard(name)
	if err == nil {
		return nil, GuardNameAlreadyExists
	}

	g := &guard{
		name:   name,
		config: config,
	}

	f.mu.Lock()
	f.guards[name] = g
	f.mu.Unlock()

	return g, nil
}

func (f *fort) GetGuard(name string) (Guard, error) {
	f.mu.RLock()
	g, ok := f.guards[name]
	f.mu.RUnlock()
	if !ok {
		return nil, GuardNotFound
	}

	return g, nil
}
