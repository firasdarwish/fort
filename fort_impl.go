/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
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
