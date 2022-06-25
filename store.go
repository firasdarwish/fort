/*
 * Copyright (c) 2022 Firas M. Darwish <firas@dev.sy> .
 * LICENSE IS INCLUDED IN PROJECT FILES.
 */

package fort

type Store interface {
	GetByProps(table string, whereKeyVals map[string]any, limit int, and bool) ([]map[string]any, error)
	Insert(table string, doc map[string]any) error
	Update(table string, whereKeyVals map[string]any, limit int, and bool, newVals map[string]any) error
}
