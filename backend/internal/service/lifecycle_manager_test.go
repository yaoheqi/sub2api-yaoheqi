package service

import (
	"errors"
	"reflect"
	"testing"
)

func TestLifecycleManager_StartAndStopInReverseOrder(t *testing.T) {
	manager := NewLifecycleManager()
	var events []string
	for _, name := range []string{"first", "second", "third"} {
		name := name
		if err := manager.Register(name, func() error {
			events = append(events, "start "+name)
			return nil
		}, func() {
			events = append(events, "stop "+name)
		}); err != nil {
			t.Fatalf("Register(%q) error = %v", name, err)
		}
	}

	if err := manager.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	manager.Stop()
	manager.Stop()

	want := []string{
		"start first", "start second", "start third",
		"stop third", "stop second", "stop first",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestLifecycleManager_StartFailureRollsBack(t *testing.T) {
	manager := NewLifecycleManager()
	var events []string
	if err := manager.Register("first", func() error {
		events = append(events, "start first")
		return nil
	}, func() {
		events = append(events, "stop first")
	}); err != nil {
		t.Fatal(err)
	}
	startErr := errors.New("boom")
	if err := manager.Register("second", func() error {
		events = append(events, "start second")
		return startErr
	}, func() {
		events = append(events, "stop second")
	}); err != nil {
		t.Fatal(err)
	}

	err := manager.Start()
	if !errors.Is(err, startErr) {
		t.Fatalf("Start() error = %v, want wrapped %v", err, startErr)
	}
	want := []string{"start first", "start second", "stop second", "stop first"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestLifecycleManager_RejectsDuplicateAndLateRegistration(t *testing.T) {
	manager := NewLifecycleManager()
	if err := manager.Register("worker", func() error { return nil }, func() {}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Register("worker", func() error { return nil }, func() {}); err == nil {
		t.Fatal("duplicate Register() error = nil")
	}
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Register("late", func() error { return nil }, func() {}); err == nil {
		t.Fatal("late Register() error = nil")
	}
}
