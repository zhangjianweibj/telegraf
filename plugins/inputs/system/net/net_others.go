// +build !linux

package net

import (
	"context"

	"github.com/shirou/gopsutil/net"
)

func IOCounters(pernic bool) ([]net.IOCountersStat, error) {
	return net.IOCountersWithContext(context.Background(), pernic)
}
