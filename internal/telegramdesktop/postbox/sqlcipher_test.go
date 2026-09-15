package postbox

import (
	"crypto/aes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestDecryptSQLCipherPagePreservesZeroSQLiteLockingPage(t *testing.T) {
	for pageSize := 512; pageSize <= 65536; pageSize *= 2 {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			testSQLCipherLockingPage(t, pageSize)
		})
	}
}

func testSQLCipherLockingPage(t *testing.T, pageSize int) {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, sqlcipherKeySize))
	if err != nil {
		t.Fatal(err)
	}
	pageNo := uint32(sqlitePendingByte/pageSize + 1)
	page := make([]byte, pageSize)
	dst := make([]byte, pageSize)
	for i := range dst {
		dst[i] = 0xff
	}

	if err := decryptSQLCipherPage(block, make([]byte, sqlcipherKeySize), pageNo, pageSize, page, dst); err != nil {
		t.Fatalf("zero SQLite locking page: %v", err)
	}
	for i, b := range dst {
		if b != 0 {
			t.Fatalf("output byte %d = %d, want 0", i, b)
		}
	}

	for _, adjacent := range []uint32{pageNo - 1, pageNo + 1} {
		if err := decryptSQLCipherPage(block, make([]byte, sqlcipherKeySize), adjacent, pageSize, page, dst); err == nil {
			t.Fatalf("zero page %d outside SQLite locking page passed HMAC verification", adjacent)
		}
	}
	page[0] = 1
	if err := decryptSQLCipherPage(block, make([]byte, sqlcipherKeySize), pageNo, pageSize, page, dst); err == nil {
		t.Fatal("non-zero SQLite locking page passed HMAC verification")
	}
}

func TestDecryptSQLCipherV4Fixture(t *testing.T) {
	keyAndSalt := make([]byte, 48)
	for i := range keyAndSalt {
		keyAndSalt[i] = byte(i)
	}
	encrypted, err := os.ReadFile(filepath.Join("testdata", "sqlcipher_v4.db"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptSQLCipherV4(encrypted, keyAndSalt)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain[:len(sqliteHeader)]) != sqliteHeader {
		t.Fatalf("plaintext header = %q", plain[:len(sqliteHeader)])
	}
	path := filepath.Join(t.TempDir(), "plain.db")
	if err := os.WriteFile(path, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	var peerCount int
	if err := db.QueryRow("SELECT count(*) FROM t2 WHERE key = 100").Scan(&peerCount); err != nil {
		t.Fatal(err)
	}
	if peerCount != 1 {
		t.Fatalf("peer count = %d, want 1", peerCount)
	}
	var messageCount int
	if err := db.QueryRow("SELECT count(*) FROM t7 WHERE key = X'00000000000000640000000054b8ea8000000001'").Scan(&messageCount); err != nil {
		t.Fatal(err)
	}
	if messageCount != 1 {
		t.Fatalf("message count = %d, want 1", messageCount)
	}
}

func TestDecryptSQLCipherV4RejectsWrongKey(t *testing.T) {
	keyAndSalt := make([]byte, 48)
	for i := range keyAndSalt {
		keyAndSalt[i] = byte(i)
	}
	keyAndSalt[0] ^= 0xff
	encrypted, err := os.ReadFile(filepath.Join("testdata", "sqlcipher_v4.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptSQLCipherV4(encrypted, keyAndSalt); err == nil {
		t.Fatal("wrong key decrypted fixture")
	}
}
