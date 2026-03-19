// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"time"
)

func (c *Client) persistResolvedLocalDNSCacheEntry(cacheKey []byte, domain string, qType uint16, qClass uint16, rawResponse []byte, now time.Time) {
	if c == nil || c.localDNSCache == nil {
		return
	}

	c.localDNSCache.SetReady(cacheKey, domain, qType, qClass, rawResponse, now)
	if c.cfg.LocalDNSCachePersist {
		c.flushLocalDNSCache()
	}
}

func (c *Client) ensureLocalDNSCacheLoaded() {
	if c == nil {
		return
	}
	c.localDNSCacheLoadOnce.Do(func() {
		c.loadLocalDNSCache()
	})
}

func (c *Client) ensureLocalDNSCachePersistence(ctx context.Context) {
	if c == nil {
		return
	}
	c.ensureLocalDNSCacheLoaded()
	c.localDNSCacheFlushOnce.Do(func() {
		go c.runLocalDNSCacheFlushLoop(ctx)
	})
}

func (c *Client) loadLocalDNSCache() {
	if c == nil || !c.cfg.LocalDNSCachePersist || c.localDNSCache == nil {
		return
	}

	loaded, err := c.localDNSCache.LoadFromFile(c.cfg.LocalDNSCachePath(), c.now())
	if err != nil {
		if c.log != nil {
			c.log.Warnf("\U0001F4BE <cyan>Local DNS Cache</cyan> <magenta>|</magenta> <red>Load Failed</red> <magenta>|</magenta> <yellow>%v</yellow>", err)
		}
		return
	}
	if loaded > 0 && c.log != nil {
		c.log.Infof("\U0001F4BE <cyan>Local DNS Cache</cyan> <magenta>|</magenta> <green>Loaded</green>: <magenta>%d</magenta>", loaded)
	}
}

func (c *Client) flushLocalDNSCache() {
	if c == nil || !c.cfg.LocalDNSCachePersist || c.localDNSCache == nil {
		return
	}

	saved, err := c.localDNSCache.SaveToFile(c.cfg.LocalDNSCachePath(), c.now())
	if err != nil {
		if c.log != nil {
			c.log.Warnf("\U0001F4BE <cyan>Local DNS Cache</cyan> <magenta>|</magenta> <red>Flush Failed</red> <magenta>|</magenta> <yellow>%v</yellow>", err)
		}
		return
	}
	if saved > 0 && c.log != nil {
		c.log.Debugf("\U0001F4BE <cyan>Local DNS Cache</cyan> <magenta>|</magenta> <green>Flushed</green>: <magenta>%d</magenta>", saved)
	}
}

func (c *Client) runLocalDNSCacheFlushLoop(ctx context.Context) {
	if c == nil || !c.cfg.LocalDNSCachePersist || c.localDNSCache == nil {
		return
	}

	interval := time.Duration(c.cfg.LocalDNSCacheFlushSec * float64(time.Second))
	if interval <= 0 {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer c.flushLocalDNSCache()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.flushLocalDNSCache()
		}
	}
}
