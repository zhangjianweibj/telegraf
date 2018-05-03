// +build linux

package net

// ReadLines reads contents from a file and splits them by new lines.
import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/net"
)

// A convenience wrapper to ReadLinesOffsetN(filename, 0, -1).
func ReadLines(filename string) ([]string, error) {
	return ReadLinesOffsetN(filename, 0, -1)
}

// ReadLines reads contents from file and splits them by new line.
// The offset tells at which line number to start.
// The count determines the number of lines to read (starting from offset):
//   n >= 0: at most n lines
//   n < 0: whole file
func ReadLinesOffsetN(filename string, offset uint, n int) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return []string{""}, err
	}
	defer f.Close()

	dr := bufio.NewReader(f)
	octets, err := ioutil.ReadAll(dr)
	if err != nil {
		panic(err)
	}

	of, err := os.OpenFile("/tmp/telegraf-debug", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(of, time.Now().UnixNano())
	fmt.Fprintln(of, string(octets))
	of.Close()

	pos, err := f.Seek(0, 0)
	if err != nil || pos != 0 {
		panic(err)
	}

	var ret []string

	r := bufio.NewReader(f)
	for i := 0; i < n+int(offset) || n < 0; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		if i < int(offset) {
			continue
		}
		ret = append(ret, strings.Trim(line, "\n"))
	}

	return ret, nil
}

func IOCounters(pernic bool) ([]net.IOCountersStat, error) {
	return IOCountersWithContext(context.Background(), pernic)
}

//GetEnv retrieves the environment variable key. If it does not exist it returns the default.
func GetEnv(key string, dfault string, combineWith ...string) string {
	value := os.Getenv(key)
	if value == "" {
		value = dfault
	}

	switch len(combineWith) {
	case 0:
		return value
	case 1:
		return filepath.Join(value, combineWith[0])
	default:
		all := make([]string, len(combineWith)+1)
		all[0] = value
		copy(all[1:], combineWith)
		return filepath.Join(all...)
	}
}

func HostProc(combineWith ...string) string {
	return GetEnv("HOST_PROC", "/proc", combineWith...)
}

func IOCountersWithContext(ctx context.Context, pernic bool) ([]net.IOCountersStat, error) {
	filename := HostProc("net/dev")
	return IOCountersByFile(pernic, filename)
}

func IOCountersByFile(pernic bool, filename string) ([]net.IOCountersStat, error) {
	return IOCountersByFileWithContext(context.Background(), pernic, filename)
}

func IOCountersByFileWithContext(ctx context.Context, pernic bool, filename string) ([]net.IOCountersStat, error) {
	lines, err := ReadLines(filename)
	if err != nil {
		return nil, err
	}

	parts := make([]string, 2)

	statlen := len(lines) - 1

	ret := make([]net.IOCountersStat, 0, statlen)

	for _, line := range lines[2:] {
		separatorPos := strings.LastIndex(line, ":")
		if separatorPos == -1 {
			continue
		}
		parts[0] = line[0:separatorPos]
		parts[1] = line[separatorPos+1:]

		interfaceName := strings.TrimSpace(parts[0])
		if interfaceName == "" {
			continue
		}

		fields := strings.Fields(strings.TrimSpace(parts[1]))
		bytesRecv, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return ret, err
		}
		packetsRecv, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return ret, err
		}
		errIn, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return ret, err
		}
		dropIn, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			return ret, err
		}
		fifoIn, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			return ret, err
		}
		bytesSent, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return ret, err
		}
		packetsSent, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return ret, err
		}
		errOut, err := strconv.ParseUint(fields[10], 10, 64)
		if err != nil {
			return ret, err
		}
		dropOut, err := strconv.ParseUint(fields[11], 10, 64)
		if err != nil {
			return ret, err
		}
		fifoOut, err := strconv.ParseUint(fields[12], 10, 64)
		if err != nil {
			return ret, err
		}

		nic := net.IOCountersStat{
			Name:        interfaceName,
			BytesRecv:   bytesRecv,
			PacketsRecv: packetsRecv,
			Errin:       errIn,
			Dropin:      dropIn,
			Fifoin:      fifoIn,
			BytesSent:   bytesSent,
			PacketsSent: packetsSent,
			Errout:      errOut,
			Dropout:     dropOut,
			Fifoout:     fifoOut,
		}
		ret = append(ret, nic)
	}

	if pernic == false {
		return getIOCountersAll(ret)
	}

	return ret, nil
}

func getIOCountersAll(n []net.IOCountersStat) ([]net.IOCountersStat, error) {
	r := net.IOCountersStat{
		Name: "all",
	}
	for _, nic := range n {
		r.BytesRecv += nic.BytesRecv
		r.PacketsRecv += nic.PacketsRecv
		r.Errin += nic.Errin
		r.Dropin += nic.Dropin
		r.BytesSent += nic.BytesSent
		r.PacketsSent += nic.PacketsSent
		r.Errout += nic.Errout
		r.Dropout += nic.Dropout
	}

	return []net.IOCountersStat{r}, nil
}
