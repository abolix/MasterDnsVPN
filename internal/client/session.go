// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"masterdnsvpn-go/internal/compression"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var (
	ErrSessionInitFailed = errors.New("session init failed")
	ErrSessionInitBusy   = errors.New("session init busy")
)

const (
	sessionInitPayloadSize   = 10
	sessionAcceptPayloadSize = 7
	sessionBusyPayloadSize   = 4
)

func (c *Client) InitializeSession(maxAttempts int) error {
	if c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {
		return ErrSessionInitFailed
	}

	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.initializeSessionOnce(); err == nil {
			return nil
		} else if errors.Is(err, ErrNoValidConnections) || errors.Is(err, ErrSessionInitBusy) {
			return err
		}
	}

	return ErrSessionInitFailed
}

func (c *Client) initializeSessionOnce() error {
	conn, initPayload, verifyCode, err := c.nextSessionInitAttempt()
	if err != nil {
		return err
	}

	query, err := c.buildSessionQuery(conn.Domain, Enums.PACKET_SESSION_INIT, initPayload)
	if err != nil {
		return ErrSessionInitFailed
	}

	packet, err := c.exchangeDNSOverConnection(conn, query, c.mtuTestTimeout)
	if err != nil {
		return ErrSessionInitFailed
	}

	switch packet.PacketType {
	case Enums.PACKET_SESSION_BUSY:
		if len(packet.Payload) < sessionBusyPayloadSize || !bytes.Equal(packet.Payload[:sessionBusyPayloadSize], verifyCode[:]) {
			return ErrSessionInitFailed
		}
		c.setSessionInitBusyUntil(time.Now().Add(sessionInitBusyRetryInterval))
		return ErrSessionInitBusy
	case Enums.PACKET_SESSION_ACCEPT:
		if len(packet.Payload) < sessionAcceptPayloadSize || !bytes.Equal(packet.Payload[3:7], verifyCode[:]) {
			return ErrSessionInitFailed
		}

		c.sessionID = packet.Payload[0]
		c.sessionCookie = packet.Payload[1]
		c.responseMode = initPayload[0]
		c.uploadCompression, c.downloadCompression = compression.SplitPair(packet.Payload[2])
		c.sessionReady = true
		c.applySessionCompressionPolicy()
		c.clearSessionInitBusyUntil()
		c.resetSessionInitState()
		c.clearReconnectPending()
		return nil
	default:
		return ErrSessionInitFailed
	}
}

func (c *Client) buildSessionInitPayload() ([]byte, bool, [4]byte, error) {
	var verifyCode [4]byte
	randomPart, err := randomBytes(len(verifyCode))
	if err != nil {
		return nil, false, verifyCode, err
	}
	copy(verifyCode[:], randomPart)

	// Use pool for temporary buffer to avoid allocation
	buf := c.udpBufferPool.Get().([]byte)
	defer c.udpBufferPool.Put(buf)

	if sessionInitPayloadSize > len(buf) {
		return nil, false, verifyCode, errors.New("buffer pool slice too small")
	}

	payload := make([]byte, sessionInitPayloadSize)
	if c.cfg.BaseEncodeData {
		payload[0] = mtuProbeBase64Reply
	}
	payload[1] = compression.PackPair(c.uploadCompression, c.downloadCompression)
	binary.BigEndian.PutUint16(payload[2:4], uint16(c.syncedUploadMTU))
	binary.BigEndian.PutUint16(payload[4:6], uint16(c.syncedDownloadMTU))
	copy(payload[6:10], verifyCode[:])
	return payload, payload[0] == mtuProbeBase64Reply, verifyCode, nil
}

func (c *Client) nextSessionInitAttempt() (Connection, []byte, [4]byte, error) {
	var empty [4]byte
	if c == nil {
		return Connection{}, nil, empty, ErrSessionInitFailed
	}

	c.initStateMu.Lock()
	defer c.initStateMu.Unlock()

	// Persistence Check: reuse existing token/payload if already ready
	if !c.sessionInitReady {
		payload, responseBase64, verifyCode, err := c.buildSessionInitPayload()
		if err != nil {
			return Connection{}, nil, empty, err
		}
		c.sessionInitPayload = payload
		c.sessionInitBase64 = responseBase64
		c.sessionInitVerify = verifyCode
		c.sessionInitReady = true
		c.sessionInitCursor = 0
	}

	snap := c.balancer.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, nil, empty, ErrNoValidConnections
	}

	// Use the cursor to rotate between valid resolvers in a Round-Robin fashion
	validLen := len(snap.valid)
	start := c.sessionInitCursor
	for checked := 0; checked < validLen; checked++ {
		idxInValid := (start + checked) % validLen
		connIdx := snap.valid[idxInValid]

		if connIdx < 0 || connIdx >= len(c.connections) {
			continue
		}

		conn := c.connections[connIdx]
		if !conn.IsValid {
			continue
		}

		c.sessionInitCursor = (idxInValid + 1) % validLen
		return conn, c.sessionInitPayload, c.sessionInitVerify, nil
	}

	return Connection{}, nil, empty, ErrNoValidConnections
}

func (c *Client) resetSessionInitState() {
	if c == nil {
		return
	}
	c.initStateMu.Lock()
	c.sessionInitPayload = nil
	c.sessionInitVerify = [4]byte{}
	c.sessionInitBase64 = false
	c.sessionInitReady = false
	c.sessionInitCursor = 0
	c.initStateMu.Unlock()
}

func (c *Client) setSessionInitBusyUntil(deadline time.Time) {
	if c == nil {
		return
	}
	c.sessionInitBusyUnix.Store(deadline.UnixNano())
}

func (c *Client) clearSessionInitBusyUntil() {
	if c == nil {
		return
	}
	c.sessionInitBusyUnix.Store(0)
}

func (c *Client) sessionInitBusyUntil() time.Time {
	if c == nil {
		return time.Time{}
	}
	unixNano := c.sessionInitBusyUnix.Load()
	if unixNano <= 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano)
}

func (c *Client) buildSessionQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelQuery(domain, 0, packetType, payload)
}

func (c *Client) buildTunnelQuery(domain string, sessionID uint8, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQueryRaw(domain, VpnProto.BuildOptions{
		SessionID:  sessionID,
		PacketType: packetType,
		Payload:    payload,
	})
}
