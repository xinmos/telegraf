//go:generate ../../../tools/readme_config_includer/generator
package cisco_telemetry_mdt

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/influxdata/telegraf/metric"
	"io"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	dialout "github.com/cisco-ie/nx-telemetry-proto/mdt_dialout"
	telemetry "github.com/cisco-ie/nx-telemetry-proto/telemetry_bis"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip" // Required to allow gzip encoding
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	internaltls "github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleConfig string

const (
	// Maximum telemetry payload size (in bytes) to accept for GRPC dialout transport
	tcpMaxMsgLen uint32 = 1024 * 1024
)

// default minimum time between successive pings
// this value is specified in the GRPC docs via GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS
const defaultKeepaliveMinTime = config.Duration(time.Second * 300)

type GRPCEnforcementPolicy struct {
	PermitKeepaliveWithoutCalls bool            `toml:"permit_keepalive_without_calls"`
	KeepaliveMinTime            config.Duration `toml:"keepalive_minimum_time"`
}

// CiscoTelemetryMDT plugin for IOS XR, IOS XE and NXOS platforms
type CiscoTelemetryMDT struct {
	// Common configuration
	Transport         string
	ServiceAddress    string                `toml:"service_address"`
	MaxMsgSize        int                   `toml:"max_msg_size"`
	Aliases           map[string]string     `toml:"aliases"`
	Dmes              map[string]string     `toml:"dmes"`
	EmbeddedTags      []string              `toml:"embedded_tags"`
	EnforcementPolicy GRPCEnforcementPolicy `toml:"grpc_enforcement_policy"`

	Log telegraf.Logger

	// GRPC TLS settings
	internaltls.ServerConfig

	// Internal listener / client handle
	grpcServer *grpc.Server
	listener   net.Listener

	// Internal state
	internalAliases map[string]string
	dmesFuncs       map[string]string
	warned          map[string]struct{}
	extraTags       map[string]map[string]struct{}
	nxpathMap       map[string]map[string]string //per path map
	propMap         map[string]func(field *telemetry.TelemetryField, value interface{}) interface{}
	mutex           sync.Mutex
	acc             telegraf.Accumulator
	wg              sync.WaitGroup

	// Though unused in the code, required by protoc-gen-go-grpc to maintain compatibility
	dialout.UnimplementedGRPCMdtDialoutServer
}

type NxPayloadXfromStructure struct {
	Name string `json:"Name"`
	Prop []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	} `json:"prop"`
}

func (*CiscoTelemetryMDT) SampleConfig() string {
	return sampleConfig
}

// Start the Cisco MDT service
func (c *CiscoTelemetryMDT) Start(acc telegraf.Accumulator) error {
	var err error
	c.acc = acc
	c.listener, err = net.Listen("tcp", c.ServiceAddress)
	if err != nil {
		return err
	}

	c.propMap = make(map[string]func(field *telemetry.TelemetryField, value interface{}) interface{}, 100)
	c.propMap["test"] = nxosValueXformUint64Toint64
	c.propMap["asn"] = nxosValueXformUint64ToString            //uint64 to string.
	c.propMap["subscriptionId"] = nxosValueXformUint64ToString //uint64 to string.
	c.propMap["operState"] = nxosValueXformUint64ToString      //uint64 to string.

	// Invert aliases list
	c.warned = make(map[string]struct{})
	c.internalAliases = make(map[string]string, len(c.Aliases))
	for alias, encodingPath := range c.Aliases {
		c.internalAliases[encodingPath] = alias
	}
	c.initDb()

	c.dmesFuncs = make(map[string]string, len(c.Dmes))
	for dme, dmeKey := range c.Dmes {
		c.dmesFuncs[dmeKey] = dme
		switch dmeKey {
		case "uint64 to int":
			c.propMap[dme] = nxosValueXformUint64Toint64
		case "uint64 to string":
			c.propMap[dme] = nxosValueXformUint64ToString
		case "string to float64":
			c.propMap[dme] = nxosValueXformStringTofloat
		case "string to uint64":
			c.propMap[dme] = nxosValueXformStringToUint64
		case "string to int64":
			c.propMap[dme] = nxosValueXformStringToInt64
		case "auto-float-xfrom":
			c.propMap[dme] = nxosValueAutoXformFloatProp
		default:
			if !strings.HasPrefix(dme, "dnpath") { // not path based property map
				continue
			}

			var jsStruct NxPayloadXfromStructure
			err := json.Unmarshal([]byte(dmeKey), &jsStruct)
			if err != nil {
				continue
			}

			// Build 2 level Hash nxpathMap Key = jsStruct.Name, Value = map of jsStruct.Prop
			// It will override the default of code if same path is provided in configuration.
			c.nxpathMap[jsStruct.Name] = make(map[string]string, len(jsStruct.Prop))
			for _, prop := range jsStruct.Prop {
				c.nxpathMap[jsStruct.Name][prop.Key] = prop.Value
			}
		}
	}

	// Fill extra tags
	c.extraTags = make(map[string]map[string]struct{})
	for _, tag := range c.EmbeddedTags {
		dir := strings.ReplaceAll(path.Dir(tag), "-", "_")
		if _, hasKey := c.extraTags[dir]; !hasKey {
			c.extraTags[dir] = make(map[string]struct{})
		}
		c.extraTags[dir][path.Base(tag)] = struct{}{}
	}

	switch c.Transport {
	case "tcp":
		// TCP dialout server accept routine
		c.wg.Add(1)
		go func() {
			c.acceptTCPClients()
			c.wg.Done()
		}()

	case "grpc":
		var opts []grpc.ServerOption
		tlsConfig, err := c.ServerConfig.TLSConfig()
		if err != nil {
			//nolint:errcheck,revive // we cannot do anything if the closing fails
			c.listener.Close()
			return err
		} else if tlsConfig != nil {
			opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		}

		if c.MaxMsgSize > 0 {
			opts = append(opts, grpc.MaxRecvMsgSize(c.MaxMsgSize))
		}

		if c.EnforcementPolicy.PermitKeepaliveWithoutCalls ||
			(c.EnforcementPolicy.KeepaliveMinTime != 0 && c.EnforcementPolicy.KeepaliveMinTime != defaultKeepaliveMinTime) {
			// Only set if either parameter does not match defaults
			opts = append(opts, grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
				MinTime:             time.Duration(c.EnforcementPolicy.KeepaliveMinTime),
				PermitWithoutStream: c.EnforcementPolicy.PermitKeepaliveWithoutCalls,
			}))
		}

		c.grpcServer = grpc.NewServer(opts...)
		dialout.RegisterGRPCMdtDialoutServer(c.grpcServer, c)

		c.wg.Add(1)
		go func() {
			if err := c.grpcServer.Serve(c.listener); err != nil {
				c.Log.Errorf("serving GRPC server failed: %v", err)
			}
			c.wg.Done()
		}()

	default:
		//nolint:errcheck,revive // we cannot do anything if the closing fails
		c.listener.Close()
		return fmt.Errorf("invalid Cisco MDT transport: %s", c.Transport)
	}

	return nil
}

// AcceptTCPDialoutClients defines the TCP dialout server main routine
func (c *CiscoTelemetryMDT) acceptTCPClients() {
	// Keep track of all active connections, so we can close them if necessary
	var mutex sync.Mutex
	clients := make(map[net.Conn]struct{})

	for {
		conn, err := c.listener.Accept()
		if neterr, ok := err.(*net.OpError); ok && (neterr.Timeout() || neterr.Temporary()) {
			continue
		} else if err != nil {
			break // Stop() will close the connection so Accept() will fail here
		}

		mutex.Lock()
		clients[conn] = struct{}{}
		mutex.Unlock()

		// Individual client connection routine
		c.wg.Add(1)
		go func() {
			c.Log.Debugf("Accepted Cisco MDT TCP dialout connection from %s", conn.RemoteAddr())
			if err := c.handleTCPClient(conn); err != nil {
				c.acc.AddError(err)
			}
			c.Log.Debugf("Closed Cisco MDT TCP dialout connection from %s", conn.RemoteAddr())

			mutex.Lock()
			delete(clients, conn)
			mutex.Unlock()

			if err := conn.Close(); err != nil {
				c.Log.Warnf("closing connection failed: %v", err)
			}
			c.wg.Done()
		}()
	}

	// Close all remaining client connections
	mutex.Lock()
	for client := range clients {
		if err := client.Close(); err != nil {
			c.Log.Errorf("Failed to close TCP dialout client: %v", err)
		}
	}
	mutex.Unlock()
}

// Handle a TCP telemetry client
func (c *CiscoTelemetryMDT) handleTCPClient(conn net.Conn) error {
	// TCP Dialout telemetry framing header
	var hdr struct {
		MsgType       uint16
		MsgEncap      uint16
		MsgHdrVersion uint16
		MsgFlags      uint16
		MsgLen        uint32
	}

	var payload bytes.Buffer
	sourceIp := conn.RemoteAddr().String()

	for {
		// Read and validate dialout telemetry header
		if err := binary.Read(conn, binary.BigEndian, &hdr); err != nil {
			return err
		}

		maxMsgSize := tcpMaxMsgLen
		if c.MaxMsgSize > 0 {
			maxMsgSize = uint32(c.MaxMsgSize)
		}

		if hdr.MsgLen > maxMsgSize {
			return fmt.Errorf("dialout packet too long: %v", hdr.MsgLen)
		} else if hdr.MsgFlags != 0 {
			return fmt.Errorf("invalid dialout flags: %v", hdr.MsgFlags)
		}

		// Read and handle telemetry packet
		payload.Reset()
		if size, err := payload.ReadFrom(io.LimitReader(conn, int64(hdr.MsgLen))); size != int64(hdr.MsgLen) {
			if err != nil {
				return err
			}
			return fmt.Errorf("TCP dialout premature EOF")
		}

		c.handleTelemetry(payload.Bytes(), sourceIp)
	}
}

// MdtDialout RPC server method for grpc-dialout transport
func (c *CiscoTelemetryMDT) MdtDialout(stream dialout.GRPCMdtDialout_MdtDialoutServer) error {
	peerInCtx, peerOK := peer.FromContext(stream.Context())
	if peerOK {
		c.Log.Debugf("Accepted Cisco MDT GRPC dialout connection from %s", peerInCtx.Addr)
	}

	var chunkBuffer bytes.Buffer
	sourceIP := peerInCtx.Addr.String()

	for {
		packet, err := stream.Recv()
		if err != nil {
			if err != io.EOF {
				c.acc.AddError(fmt.Errorf("GRPC dialout receive error: %v", err))
			}
			break
		}

		if len(packet.Data) == 0 && len(packet.Errors) != 0 {
			c.acc.AddError(fmt.Errorf("GRPC dialout error: %s", packet.Errors))
			break
		}

		// Reassemble chunked telemetry data received from NX-OS
		if packet.TotalSize == 0 {
			c.handleTelemetry(packet.Data, sourceIP)
		} else if int(packet.TotalSize) <= c.MaxMsgSize {
			if _, err := chunkBuffer.Write(packet.Data); err != nil {
				c.acc.AddError(fmt.Errorf("writing packet %q failed: %v", packet.Data, err))
			}
			if chunkBuffer.Len() >= int(packet.TotalSize) {
				c.handleTelemetry(chunkBuffer.Bytes(), sourceIP)
				chunkBuffer.Reset()
			}
		} else {
			c.acc.AddError(fmt.Errorf("dropped too large packet: %dB > %dB", packet.TotalSize, c.MaxMsgSize))
		}
	}

	if peerOK {
		c.Log.Debugf("Closed Cisco MDT GRPC dialout connection from %s", peerInCtx.Addr)
	}

	return nil
}

// Handle telemetry packet from any transport, decode and add as measurement
func (c *CiscoTelemetryMDT) handleTelemetry(data []byte, sourceIP string) {
	msg := &telemetry.Telemetry{}
	err := proto.Unmarshal(data, msg)
	if err != nil {
		c.acc.AddError(fmt.Errorf("failed to decode: %v", err))
		return
	}

	grouper := metric.NewGrouper()
	gbpkv, err := json.Marshal(msg)
	if err != nil {
		c.Log.Errorf("Gpbkv Parse Failure")
	}

	field := metric.NewField()
	field.GbpkvParse(gbpkv, sourceIP)
	timestamp := time.Unix(int64(msg.MsgTimestamp/1000), int64(msg.MsgTimestamp%1000)*1000000)

	if err := grouper.Add(msg.EncodingPath, timestamp, "Telemetry", field.Telemetry); err != nil {
		c.Log.Errorf("adding field %q to group failed: Telemetry", err)
	}
	if err := grouper.Add(msg.EncodingPath, timestamp, "Rows", field.Rows); err != nil {
		c.Log.Errorf("adding field %q to group failed: rows", err)
	}
	if err := grouper.Add(msg.EncodingPath, timestamp, "Source", field.Source); err != nil {
		c.Log.Errorf("adding field %q to group failed: Source", err)
	}

	for _, groupedMetric := range grouper.Metrics() {
		c.acc.AddMetric(groupedMetric)
	}
}

func (c *CiscoTelemetryMDT) Address() net.Addr {
	return c.listener.Addr()
}

// Stop listener and cleanup
func (c *CiscoTelemetryMDT) Stop() {
	if c.grpcServer != nil {
		// Stop server and terminate all running dialout routines
		//nolint:errcheck,revive // we cannot do anything if the stopping fails
		c.grpcServer.Stop()
	}
	if c.listener != nil {
		//nolint:errcheck,revive // we cannot do anything if the closing fails
		c.listener.Close()
	}
	c.wg.Wait()
}

// Gather plugin measurements (unused)
func (c *CiscoTelemetryMDT) Gather(_ telegraf.Accumulator) error {
	return nil
}

func init() {
	inputs.Add("cisco_telemetry_mdt", func() telegraf.Input {
		return &CiscoTelemetryMDT{
			Transport:      "grpc",
			ServiceAddress: "127.0.0.1:57000",
		}
	})
}
