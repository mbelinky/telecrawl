package telegramdesktop

import (
	"testing"

	querymessages "github.com/gotd/td/telegram/query/messages"
	"github.com/gotd/td/tg"
)

func TestTelegramMessageFileTreatsBrokenMediaAsNoFile(t *testing.T) {
	// A document message whose Document field is nil makes gotd's Elem.File
	// dereference a nil pointer; the importer must see "no file", not crash.
	elem := querymessages.Elem{Msg: &tg.Message{Media: &tg.MessageMediaDocument{}}}
	if _, ok := telegramMessageFile(elem); ok {
		t.Fatal("expected no file for a document message without a document")
	}
	empty := querymessages.Elem{Msg: &tg.Message{}}
	if _, ok := telegramMessageFile(empty); ok {
		t.Fatal("expected no file for a message without media")
	}
}

