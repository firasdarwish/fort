/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

import "sync"

type fort struct {
	guards map[string]*guard

	mu *sync.RWMutex
}

type Fort interface {
	NewGuard(name string, config *GuardConfig) (Guard, error)
	GetGuard(name string) (Guard, error)
}

func New() Fort {
	return &fort{
		guards: map[string]*guard{},
		mu:     &sync.RWMutex{},
	}
}
