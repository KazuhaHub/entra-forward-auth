package version

import "testing"

func TestString(t *testing.T) {
	oldV, oldR := Version, Revision
	t.Cleanup(func() { Version, Revision = oldV, oldR })

	Version, Revision = "1.2.3", "abc"
	if got, want := String(), "1.2.3 (abc)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestDefaults(t *testing.T) {
	if Version == "" || Revision == "" {
		t.Fatal("defaults must not be empty")
	}
}
