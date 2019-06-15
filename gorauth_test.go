package gorauth

import (
	"os"
	"testing"
)

func TestEnvs(t *testing.T) {
	// setup
	want := "sqlite3" + "credstore"

	// execution
	dr := os.Getenv("GOR_AUTH_DBDRIVER")
	db := os.Getenv("GOR_AUTH_DBNAME")

	if dr == "" {
		dr = "sqlite3"
	}
	if db == "" {
		db = "credstore"
	}

	got := dr + db
	// verify
	if want != got {
		t.Errorf("got: %v; want %v", got, want)
	}
}
