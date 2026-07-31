package service

import (
	"fmt"
	"sync"
)

type lifecycleComponent struct {
	name  string
	start func() error
	stop  func()
}

// LifecycleManager starts registered background services together and stops
// successfully started services in reverse order.
type LifecycleManager struct {
	mu         sync.Mutex
	components []lifecycleComponent
	names      map[string]struct{}
	started    []lifecycleComponent
	starting   bool

	startOnce sync.Once
	startErr  error
	stopOnce  sync.Once
}

func NewLifecycleManager() *LifecycleManager {
	return &LifecycleManager{names: make(map[string]struct{})}
}

func (m *LifecycleManager) Register(name string, start func() error, stop func()) error {
	if m == nil {
		return fmt.Errorf("register lifecycle component %q: manager is nil", name)
	}
	if name == "" {
		return fmt.Errorf("register lifecycle component: name is required")
	}
	if start == nil || stop == nil {
		return fmt.Errorf("register lifecycle component %q: start and stop are required", name)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.starting {
		return fmt.Errorf("register lifecycle component %q: lifecycle already started", name)
	}
	if _, exists := m.names[name]; exists {
		return fmt.Errorf("register lifecycle component %q: duplicate name", name)
	}
	m.names[name] = struct{}{}
	m.components = append(m.components, lifecycleComponent{name: name, start: start, stop: stop})
	return nil
}

func (m *LifecycleManager) Start() error {
	if m == nil {
		return fmt.Errorf("start lifecycle: manager is nil")
	}
	m.startOnce.Do(func() {
		m.mu.Lock()
		m.starting = true
		components := append([]lifecycleComponent(nil), m.components...)
		m.mu.Unlock()

		for _, component := range components {
			if err := component.start(); err != nil {
				component.stop()
				m.startErr = fmt.Errorf("start lifecycle component %q: %w", component.name, err)
				m.Stop()
				return
			}
			m.mu.Lock()
			m.started = append(m.started, component)
			m.mu.Unlock()
		}
	})
	return m.startErr
}

func (m *LifecycleManager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		m.mu.Lock()
		started := append([]lifecycleComponent(nil), m.started...)
		m.mu.Unlock()
		for i := len(started) - 1; i >= 0; i-- {
			started[i].stop()
		}
	})
}

// LifecycleRuntime keeps the managed services reachable in the Wire graph.
type LifecycleRuntime struct {
	manager *LifecycleManager
}

func (r *LifecycleRuntime) Stop() {
	if r != nil {
		r.manager.Stop()
	}
}
