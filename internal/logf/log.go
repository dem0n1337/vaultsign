// Package logf provides file logging with Vault token redaction.
package logf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var (
	hvsRe = regexp.MustCompile(`(hvs\.|hvb\.|hvr\.)[A-Za-z0-9_-]+`)
	sRe   = regexp.MustCompile(`(^|[^\w])(s\.)[A-Za-z0-9_-]{20,}`)
)

// Redact removes Vault tokens from text so they never reach disk.
func Redact(text string) string {
	text = hvsRe.ReplaceAllString(text, "$1***REDACTED***")
	text = sRe.ReplaceAllString(text, "$1$2***REDACTED***")
	return text
}

const (
	maxBytes = 1_000_000
	backups  = 3
)

// Logger writes redacted, timestamped lines to a rotating file.
type Logger struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// New opens the log at ~/.local/share/vaultsign/vaultsign.log (0600).
func New() (*Logger, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".local", "share", "vaultsign")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Logger{path: filepath.Join(dir, "vaultsign.log")}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	l.f = f
	return nil
}

func (l *Logger) rotateIfNeeded() {
	fi, err := l.f.Stat()
	if err != nil || fi.Size() < maxBytes {
		return
	}
	l.f.Close()
	for i := backups; i >= 1; i-- {
		src := l.path
		if i > 1 {
			src = fmt.Sprintf("%s.%d", l.path, i-1)
		}
		dst := fmt.Sprintf("%s.%d", l.path, i)
		os.Rename(src, dst)
	}
	l.open()
}

// Infof writes a redacted INFO line.
func (l *Logger) Infof(format string, args ...any) {
	l.write("INFO", fmt.Sprintf(format, args...))
}

// Step logs a named step result in the "[name] OK/FAILED" format.
func (l *Logger) Step(name string, ok bool, detail string) {
	status := "FAILED"
	if ok {
		status = "OK"
	}
	l.write("INFO", fmt.Sprintf("[%s] %s", name, status))
	if detail != "" {
		l.write("INFO", detail)
	}
}

func (l *Logger) write(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	l.rotateIfNeeded()
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), level, Redact(msg))
	l.f.WriteString(line)
}

// Close flushes and closes the log file.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}
