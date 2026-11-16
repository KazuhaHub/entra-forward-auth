// Package version holds build information injected at link time:
//
//	go build -ldflags "-X github.com/KazuhaHub/entra-forward-auth/internal/version.Version=1.2.3 \
//	  -X github.com/KazuhaHub/entra-forward-auth/internal/version.Revision=abcdef0"
package version

// Version is the release version, or "dev" for local builds.
var Version = "dev"

// Revision is the source control revision, or "unknown" when not injected.
var Revision = "unknown"

// String returns a human-readable "version (revision)" string.
func String() string {
	return Version + " (" + Revision + ")"
}
