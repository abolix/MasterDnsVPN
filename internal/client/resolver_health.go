package client

import (
	"context"
	"time"

	"masterdnsvpn-go/internal/logger"
)

type resolverHealthEvent struct {
	At time.Time
}

type resolverHealthState struct {
	Events           []resolverHealthEvent
	TimeoutOnlySince time.Time
	LastSuccessAt    time.Time
}

type resolverAutoDisableCandidate struct {
	key            string
	eventCount     int
	span           time.Duration
	oldestAge      time.Duration
	timeoutOnlyAge time.Duration
}

func (c *Client) initResolverRecheckMeta() {
	if c == nil || c.runtime == nil {
		return
	}

	c.resolverStatsMu.Lock()
	c.resolverPending = make(map[resolverSampleKey]resolverSample)
	c.resolverStatsMu.Unlock()

	c.runtime.healthMu.Lock()
	defer c.runtime.healthMu.Unlock()

	allConns := c.balancer.AllConnections()
	c.runtime.health = make(map[string]*resolverHealthState, len(allConns))

	for _, conn := range allConns {
		if conn.Key == "" {
			continue
		}
		c.runtime.health[conn.Key] = &resolverHealthState{
			Events: make([]resolverHealthEvent, 0, 8),
		}
	}
}

func (c *Client) runResolverHealthLoop(ctx context.Context) {
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
		}

		now := c.now()
		c.collectExpiredResolverTimeouts(now)
		c.runResolverAutoDisable(now)
		c.runResolverRecheckBatch(ctx, now)

		waitFor := 2 * time.Second
		if c.cfg.AutoDisableTimeoutServers {
			checkInterval := c.autoDisableCheckInterval()
			if checkInterval < waitFor {
				waitFor = checkInterval
			}
		}
		if c.cfg.RecheckInactiveServersEnabled && c.successMTUChecks {
			pollInterval := c.inactiveHealthCheckPollInterval()
			if pollInterval < waitFor {
				waitFor = pollInterval
			}
		}
		if waitFor < 250*time.Millisecond {
			waitFor = 250 * time.Millisecond
		} else if waitFor > 5*time.Second {
			waitFor = 5 * time.Second
		}

		timer := time.NewTimer(waitFor)
		if ctx == nil {
			<-timer.C
			continue
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *Client) noteResolverTimeout(serverKey string, at time.Time) {
	if c == nil || serverKey == "" {
		return
	}
	if at.IsZero() {
		at = c.now()
	}
	c.runtime.NoteTimeout(serverKey, at, c.autoDisableTimeoutWindow())
}

func (c *Client) noteResolverFailure(serverKey string, at time.Time) {
	if c == nil || serverKey == "" {
		return
	}
	if at.IsZero() {
		at = c.now()
	}
	c.runtime.NoteFailure(serverKey, at, c.autoDisableTimeoutWindow())
}

func (c *Client) recordResolverHealthEvent(serverKey string, success bool, now time.Time) {
	if c == nil || serverKey == "" {
		return
	}
	c.runtime.RecordHealthEvent(serverKey, success, now, c.autoDisableTimeoutWindow())
}

func (c *Client) retractResolverTimeoutEvent(serverKey string, timedOutAt time.Time, now time.Time) {
	if c == nil || serverKey == "" || timedOutAt.IsZero() {
		return
	}
	c.runtime.RetractTimeoutEvent(serverKey, timedOutAt, now, c.autoDisableTimeoutWindow())
}

func (c *Client) runResolverAutoDisable(now time.Time) {
	if c == nil || !c.cfg.AutoDisableTimeoutServers || c.balancer.ActiveCount() <= 3 {
		return
	}

	window := c.autoDisableTimeoutWindow()
	debugEnabled := c.log != nil && c.log.Enabled(logger.LevelDebug)
	candidates := make([]resolverAutoDisableCandidate, 0, c.balancer.ConnectionCount())
	c.runtime.healthMu.Lock()
	for key, state := range c.runtime.health {
		if state == nil {
			continue
		}
		c.runtime.pruneHealthLocked(state, now, window)
		conn, ok := c.GetConnectionByKey(key)
		if !ok || !conn.IsValid {
			continue
		}
		if len(state.Events) < c.autoDisableMinObservations() {
			continue
		}
		if state.TimeoutOnlySince.IsZero() {
			continue
		}
		timeoutOnlyAge := now.Sub(state.TimeoutOnlySince)
		if timeoutOnlyAge < window {
			continue
		}
		candidate := resolverAutoDisableCandidate{key: key}
		if debugEnabled {
			candidate.eventCount = len(state.Events)
			candidate.span = state.Events[len(state.Events)-1].At.Sub(state.Events[0].At)
			candidate.oldestAge = now.Sub(state.Events[0].At)
			candidate.timeoutOnlyAge = timeoutOnlyAge
		}
		candidates = append(candidates, candidate)
	}
	c.runtime.healthMu.Unlock()

	if debugEnabled {
		for _, candidate := range candidates {
			c.log.Debugf(
				"\U0001F6A8 <yellow>Resolver auto-disable candidate</yellow> <magenta>|</magenta> <blue>Resolver</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Events</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Span</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>OldestAge</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>TimeoutOnlyAge</blue>: <cyan>%s</cyan>",
				candidate.key,
				candidate.eventCount,
				candidate.span.Round(time.Millisecond),
				candidate.oldestAge.Round(time.Millisecond),
				candidate.timeoutOnlyAge.Round(time.Millisecond),
			)
		}
	}

	for _, candidate := range candidates {
		if c.balancer.ActiveCount() <= 3 {
			return
		}
		c.disableResolverConnection(candidate.key, "100% timeout window")
	}
}

func (c *Client) disableResolverConnection(serverKey string, cause string) bool {
	if c == nil || serverKey == "" {
		return false
	}
	conn, ok := c.GetConnectionByKey(serverKey)
	if !ok || !conn.IsValid || c.balancer.ActiveCount() <= 3 {
		return false
	}

	setValid := c.balancer.SetConnectionValidity
	if c.runtime != nil {
		setValid = c.runtime.SetConnectionValidity
	}
	if !setValid(serverKey, false) {
		return false
	}
	if refreshed, ok := c.GetConnectionByKey(serverKey); ok {
		conn = refreshed
	}
	c.runtime.healthMu.Lock()
	delete(c.runtime.health, serverKey)
	c.runtime.healthMu.Unlock()

	c.runtime.clearPreferredResolverReferences(serverKey)
	c.balancer.ResetServerStats(serverKey)
	if c.log != nil {
		c.log.Warnf(
			"\U0001F6D1 <yellow>DNS server <cyan>%s</cyan> disabled due to: <red>%s</red></yellow> <magenta>|</magenta> <green>Active Resolvers</green>: <cyan>%d</cyan>",
			conn.ResolverLabel,
			cause,
			c.balancer.ActiveCount(),
		)
	}
	c.appendMTURemovedServerLine(&conn, cause)
	return true
}

func (c *Client) reactivateResolverConnection(serverKey string) bool {
	if c == nil || serverKey == "" {
		return false
	}
	conn, ok := c.GetConnectionByKey(serverKey)
	if !ok || conn.IsValid {
		return false
	}
	setValid := c.balancer.SetConnectionValidity
	if c.runtime != nil {
		setValid = c.runtime.SetConnectionValidity
	}
	if !setValid(serverKey, true) {
		return false
	}
	if refreshed, ok := c.GetConnectionByKey(serverKey); ok {
		conn = refreshed
	}

	c.runtime.healthMu.Lock()
	delete(c.runtime.health, serverKey)
	c.runtime.healthMu.Unlock()

	// Seed with a moderate initial score so the balancer doesn't flood the
	// just-reactivated resolver before it has proven itself. Stats were zeroed
	// when the resolver was disabled; seeding conservatively (80% delivery)
	// lets it participate immediately but at lower priority than healthy peers.
	c.balancer.SeedConservativeStats(serverKey)
	if c.log != nil {
		c.log.Infof(
			"\U0001F504 <green>DNS server <cyan>%s</cyan> re-activated after successful recheck.</green> <magenta>|</magenta> <green>Active Resolvers</green>: <cyan>%d</cyan>",
			conn.ResolverLabel,
			c.balancer.ActiveCount(),
		)
	}
	c.appendMTUAddedServerLine(&conn)
	return true
}

func (c *Client) runResolverRecheckBatch(ctx context.Context, now time.Time) {
	if c == nil || !c.cfg.RecheckInactiveServersEnabled || !c.successMTUChecks {
		return
	}

	conn, ok := c.balancer.NextInactiveConnectionForHealthCheck(now, c.recheckInactiveInterval())
	if !ok || conn.Key == "" || conn.IsValid {
		return
	}
	if !c.tryAcquireResolverRecheckSlot() {
		return
	}

	go func(cn Connection) {
		defer c.releaseResolverRecheckSlot()
		defer func() { _ = recover() }()

		if c.recheckResolverConnection(ctx, &cn) && c.applyRecheckedResolverMTU(cn.Key) {
			c.reactivateResolverConnection(cn.Key)
		}
	}(conn)
}

func (c *Client) tryAcquireResolverRecheckSlot() bool {
	if c == nil || c.runtime == nil || c.runtime.recheckSem == nil {
		return true
	}
	select {
	case c.runtime.recheckSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (c *Client) releaseResolverRecheckSlot() {
	if c == nil || c.runtime == nil || c.runtime.recheckSem == nil {
		return
	}
	select {
	case <-c.runtime.recheckSem:
	default:
	}
}

func (c *Client) recheckResolverConnection(ctx context.Context, conn *Connection) bool {
	if c == nil || conn == nil || c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {
		return false
	}
	if c.recheckConnectionFn != nil {
		if !c.recheckConnectionFn(conn) {
			return false
		}
		return true
	}

	transport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		return false
	}
	defer transport.conn.Close()

	upOK := false
	for attempt := 0; attempt < c.mtuTestRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return false
		}
		passed, _, err := c.sendUploadMTUProbe(ctx, *conn, transport, c.syncedUploadMTU, mtuProbeOptions{Quiet: true, IsRetry: attempt > 0})
		if err == nil && passed {
			upOK = true
			break
		}
	}
	if !upOK {
		return false
	}

	downOK := false
	for attempt := 0; attempt < c.mtuTestRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return false
		}
		passed, _, err := c.sendDownloadMTUProbe(ctx, *conn, transport, c.syncedDownloadMTU, c.syncedUploadMTU, mtuProbeOptions{Quiet: true, IsRetry: attempt > 0})
		if err == nil && passed {
			downOK = true
			break
		}
	}
	if !downOK {
		return false
	}

	return true
}

func (c *Client) applyRecheckedResolverMTU(serverKey string) bool {
	if c == nil || serverKey == "" {
		return false
	}

	if c.balancer == nil {
		conn := c.connectionPtrByKey(serverKey)
		if conn == nil {
			return false
		}
		conn.UploadMTUBytes = c.syncedUploadMTU
		conn.UploadMTUChars = c.encodedCharsForPayload(c.syncedUploadMTU)
		conn.DownloadMTUBytes = c.syncedDownloadMTU
		return true
	}

	if c.runtime != nil {
		return c.runtime.SetConnectionMTU(
			serverKey,
			c.syncedUploadMTU,
			c.encodedCharsForPayload(c.syncedUploadMTU),
			c.syncedDownloadMTU,
		)
	}

	return c.balancer.SetConnectionMTU(
		serverKey,
		c.syncedUploadMTU,
		c.encodedCharsForPayload(c.syncedUploadMTU),
		c.syncedDownloadMTU,
	)
}

func (c *Client) isRuntimeDisabledResolver(serverKey string) bool {
	return false
}

func (c *Client) autoDisableTimeoutWindow() time.Duration {
	return time.Duration(c.cfg.AutoDisableTimeoutWindowSeconds * float64(time.Second))
}

func (c *Client) autoDisableCheckInterval() time.Duration {
	return time.Duration(c.cfg.AutoDisableCheckIntervalSeconds * float64(time.Second))
}

func (c *Client) autoDisableMinObservations() int {
	if c.cfg.AutoDisableMinObservations < 1 {
		return 1
	}
	return c.cfg.AutoDisableMinObservations
}

func (c *Client) recheckInactiveInterval() time.Duration {
	return time.Duration(c.cfg.RecheckInactiveIntervalSeconds * float64(time.Second))
}

func (c *Client) inactiveHealthCheckPollInterval() time.Duration {
	interval := c.recheckInactiveInterval() / 4
	if interval < time.Second {
		return time.Second
	}
	if interval > 5*time.Second {
		return 5 * time.Second
	}
	return interval
}
