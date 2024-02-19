package firewall

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBadRanges(t *testing.T) {
	fw, err := New("1/2", slog.Default())
	assert.Nil(t, fw)
	assert.Error(t, err)
}

func TestAllowIfNoRanges(t *testing.T) {
	fw, err := New("", slog.Default())
	assert.NoError(t, err)
	assert.True(t, fw.Authorized("127.0.0.1:1234"))
	assert.True(t, fw.Authorized("8.8.8.8.1:234"))
	assert.True(t, fw.Authorized("10.1.2.3:34"))
	assert.True(t, fw.Authorized("[::1]:4"))
}

func TestWithRanges(t *testing.T) {
	fw, err := New("10.0.0.0/8,192.168.0.0/24,::/1", slog.Default())
	assert.NoError(t, err)
	assert.False(t, fw.Authorized("127.0.0.1:1234"))
	assert.False(t, fw.Authorized("8.8.8.8.1:234"))
	assert.True(t, fw.Authorized("10.1.2.3:34"))
	assert.True(t, fw.Authorized("[::10]:4"))
	assert.False(t, fw.Authorized("[8fff::]:40"))
}

func TestMalformedAddresses(t *testing.T) {
	fw, err := New("", slog.Default())
	assert.NoError(t, err)
	assert.True(t, fw.Authorized(":80"), "no IP address")
	assert.True(t, fw.Authorized("8.8.8.8"), "no port")

	fw, err = New("10.0.0.0/8,192.168.0.0/24,::/1", slog.Default())
	assert.NoError(t, err)
	assert.False(t, fw.Authorized(":80"), "no IP address")
	assert.False(t, fw.Authorized("10.0.0.0"), "no port")
}
