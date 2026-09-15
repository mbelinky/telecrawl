package telegramdesktop

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/openclaw/telecrawl/internal/store"
	postboxpkg "github.com/openclaw/telecrawl/internal/telegramdesktop/postbox"
	"golang.org/x/crypto/pbkdf2"
)

// Opt in with a built CLI: the real locking offset requires a >1 GiB fixture.
func TestSQLCipherLockingPageCLI(t *testing.T) {
	cli := os.Getenv("TELECRAWL_LOCKING_PROOF_BINARY")
	if cli == "" {
		t.Skip("set TELECRAWL_LOCKING_PROOF_BINARY to a built telecrawl binary (requires several GiB of RAM and disk)")
	}
	root, _, account := makePostboxFixture(t)
	path := filepath.Join(account, "postbox", "db", "db_sqlite")
	key := make([]byte, 48)
	for i := range key {
		key[i] = byte(i)
	}
	encrypted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := postboxpkg.DecryptSQLCipherV4(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	plainPath := filepath.Join(t.TempDir(), "synthetic-plain.db")
	if err := os.WriteFile(plainPath, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", plainPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TABLE padding(value BLOB)`); err != nil {
		t.Fatal(err)
	}
	for range 64 {
		if _, err := db.Exec(`INSERT INTO padding VALUES(zeroblob(16777216))`); err != nil {
			t.Fatal(err)
		}
	}
	// Place the message b-tree beyond the locking page, proving later reads too.
	if _, err := db.Exec(`CREATE TABLE later_messages AS SELECT * FROM t7; DROP TABLE t7; ALTER TABLE later_messages RENAME TO t7`); err != nil {
		t.Fatal(err)
	}
	var messagePage int
	if err := db.QueryRow(`SELECT rootpage FROM sqlite_master WHERE name='t7'`).Scan(&messagePage); err != nil {
		t.Fatal(err)
	}
	if messagePage <= 262145 {
		t.Fatalf("message page %d is not beyond the locking page", messagePage)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var plain []byte
	err = conn.Raw(func(c any) error {
		var err error
		plain, err = c.(interface{ Serialize() ([]byte, error) }).Serialize()
		return err
	})
	if closeErr := conn.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	const pageSize = 4096
	const lockingOffset = 0x40000000
	if binary.BigEndian.Uint16(plain[16:18]) != pageSize || plain[20] != 80 || len(plain)%pageSize != 0 {
		t.Fatal("unexpected SQLCipher fixture geometry")
	}
	if !bytes.Equal(plain[lockingOffset:lockingOffset+pageSize], make([]byte, pageSize)) {
		t.Fatal("SQLite did not leave its reserved locking page zero")
	}
	salt := append([]byte(nil), key[32:]...)
	for i := range salt {
		salt[i] ^= 0x3a
	}
	hmacKey := pbkdf2.Key(key[:32], salt, 2, 32, sha512.New)
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < len(plain); offset += pageSize {
		if offset == lockingOffset {
			continue
		}
		page := plain[offset : offset+pageSize]
		start := 0
		if offset == 0 {
			start = 32
		}
		const payloadEnd = pageSize - 80
		iv := sha256.Sum256([]byte(fmt.Sprintf("synthetic locking fixture page %d", offset/pageSize+1)))
		copy(page[payloadEnd:], iv[:16])
		cipher.NewCBCEncrypter(block, iv[:16]).CryptBlocks(page[start:payloadEnd], page[start:payloadEnd])
		mac := hmac.New(sha512.New, hmacKey)
		_, _ = mac.Write(page[start : payloadEnd+16])
		_, _ = mac.Write(binary.LittleEndian.AppendUint32(nil, uint32(offset/pageSize+1)))
		copy(page[payloadEnd+16:], mac.Sum(nil))
	}
	if err := os.WriteFile(path, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("synthetic source: %d bytes, locking page 262145, message root page %d", len(plain), messagePage)
	plain = nil
	archive := filepath.Join(t.TempDir(), "archive.db")
	command := exec.CommandContext(t.Context(), cli, "--json", "--db", archive, "--source", root, "import")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("built CLI import: %v\n%s", err, output)
	}
	command = exec.CommandContext(t.Context(), cli, "--json", "--db", archive, "messages")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var messages []store.Message
	if err := json.Unmarshal(output, &messages); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].Text != "fixture hello" {
		t.Fatalf("imported messages = %+v", messages)
	}
	t.Log("built CLI imported and read the synthetic message beyond the locking page")
}
