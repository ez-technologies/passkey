package gormstore_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/ez-technologies/passkey"
	"github.com/ez-technologies/passkey/gormstore"
	"github.com/ez-technologies/passkey/storetest"
)

func TestStoreSQLite(t *testing.T) {
	storetest.Run(t, func(t *testing.T) passkey.Store {
		dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatal(err)
		}
		sqlDB, _ := db.DB()
		sqlDB.SetMaxOpenConns(1) // SQLite has one writer; the race checks then queue instead of failing
		t.Cleanup(func() { _ = sqlDB.Close() })
		return migrated(t, db)
	})
}

// TestStorePostgres runs against PostgreSQL when PASSKEY_TEST_DATABASE_URL names a database. It
// uses a schema of its own and drops it afterwards.
func TestStorePostgres(t *testing.T) {
	url := os.Getenv("PASSKEY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PASSKEY_TEST_DATABASE_URL is not set")
	}
	n := 0
	storetest.Run(t, func(t *testing.T) passkey.Store {
		n++
		schema := fmt.Sprintf("passkey_test_%d_%d", os.Getpid(), n)
		admin, err := gorm.Open(postgres.Open(url), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatal(err)
		}
		if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
			t.Fatal(err)
		}
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		// Every connection of the pool uses the schema, so the race checks run on many connections.
		db, err := gorm.Open(postgres.Open(url+sep+"search_path="+schema), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			sqlDB, _ := db.DB()
			_ = sqlDB.Close()
			admin.Exec("DROP SCHEMA " + schema + " CASCADE")
			adminDB, _ := admin.DB()
			_ = adminDB.Close()
		})
		return migrated(t, db)
	})
}

func migrated(t *testing.T, db *gorm.DB) passkey.Store {
	s := gormstore.New(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}
