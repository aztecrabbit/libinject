package libinject

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aztecrabbit/liblog"
	"github.com/aztecrabbit/libredsocks"
	"github.com/aztecrabbit/libutils"
)

var (
	Loop          = true
	DefaultConfig = &Config{
		Enable: true,
		Type:   0,
		Port:   "8989",
		Rules: map[string][]string{
			"*:*": []string{
				"202.152.240.50:80",
			},
		},
		Payload:              "[raw][crlf]Host: t.co[crlf]Host: [crlf][crlf]",
		ServerNameIndication: "twitter.com",
		Timeout:              5,
		ShowLog:              false,
	}
)

type ClientRequest map[string]string

type Config struct {
	Enable               bool
	Type                 int
	Port                 string
	Rules                map[string][]string
	Payload              string
	ServerNameIndication string
	Timeout              int
	ShowLog              bool
}

type Inject struct {
	Redsocks *libredsocks.Redsocks
	Config   *Config
}

func (i *Inject) Start() {
	if i.Config.Enable == false {
		return
	}

	inject, err := net.Listen("tcp", "0.0.0.0:"+i.Config.Port)
	if err != nil {
		liblog.LogException(err, "INFO")
		os.Exit(0)
	}

	for {
		client, err := inject.Accept()
		if err != nil {
			panic(err)
		}

		go i.Forward(client)
	}
}

func (i *Inject) Forward(c net.Conn) {
	defer c.Close()

	request, err := i.ExtractClientRequest(c)
	if err != nil {
		return
	}

	switch i.Config.Type {
	case 0:
		i.TunnelType0(c, request)
	case 1:
		i.TunnelType1(c, request)
	case 2:
		i.TunnelType2(c, request)
	default:
		liblog.LogInfo("Inject type "+strconv.Itoa(i.Config.Type)+" not found!", "INFO", liblog.Colors["R1"])
	}
}

func (i *Inject) ReadResponse(r net.Conn) string {
	data := ""
	buffer := make([]byte, 65535)

	for {
		length, err := r.Read(buffer)
		if err != nil {
			break
		}
		data += string(buffer[:length])

		if strings.HasSuffix(data, "\r\n\r\n") {
			break
		}
	}

	return data
}

func (i *Inject) ExtractClientRequest(c net.Conn) (map[string]string, error) {
	buffer := make([]byte, 65535)
	length, _ := c.Read(buffer)

	payloadHeaders := strings.Split(string(buffer[:length]), "\r\n")
	payloadHeader0 := strings.Split(payloadHeaders[0], " ")

	if len(payloadHeader0) < 3 {
		return nil, errors.New("payload header 0 empty")
	}

	request := make(map[string]string)

	request["method"] = payloadHeader0[0]
	if request["method"] != "CONNECT" {
		return nil, errors.New("method not allowed!")
	}

	payloadHostPort := strings.Split(payloadHeader0[1], ":")
	request["host"] = payloadHostPort[0]
	request["port"] = payloadHostPort[1]

	request["protocol"] = payloadHeader0[2]

	return request, nil
}

func (i *Inject) GetProxyFromRule(w string) []string {
	libutils.Lock.Lock()
	defer libutils.Lock.Unlock()

	proxyAddress := i.Config.Rules[w][0]
	if len(i.Config.Rules[w]) > 1 {
		i.Config.Rules[w] = append(i.Config.Rules[w][1:], i.Config.Rules[w][0])
	}

	return strings.Split(proxyAddress, ":")
}

func (i *Inject) GetProxy(request map[string]string) ([]string, error) {
	for whitelistAddress, proxyAddressList := range i.Config.Rules {
		if strings.Contains(whitelistAddress, "#") || len(proxyAddressList) == 0 {
			continue
		}

		whitelistHostPort := strings.Split(whitelistAddress, ":")
		if len(whitelistHostPort) == 1 {
			whitelistHostPort = append(whitelistHostPort, "*")
		}

		if (whitelistHostPort[0] == "*" || strings.Contains(request["host"], whitelistHostPort[0])) &&
			(whitelistHostPort[1] == "*" || whitelistHostPort[1] == request["port"]) {
			proxyHostPort := i.GetProxyFromRule(whitelistAddress)

			if strings.HasPrefix(proxyHostPort[0], "#") {
				continue
			}
			if len(proxyHostPort) == 1 {
				proxyHostPort = append(proxyHostPort, "80")
			}
			if strings.Contains(proxyHostPort[0], "*") {
				proxyHostPort[0] = request["host"]
				proxyHostPort[1] = request["port"]
			}

			return proxyHostPort, nil
		}
	}

	return nil, errors.New("Request blocked")
}

func (i *Inject) ProxyConnect(request map[string]string) (net.Conn, error) {
	proxyHostPort, err := i.GetProxy(request)
	if err != nil {
		return nil, err
	}

	if i.Redsocks != nil {
		i.Redsocks.RuleDirectAdd(proxyHostPort[0])
	}

	var logConnecting string

	if proxyHostPort[0] == request["host"] && proxyHostPort[1] == request["port"] {
		logConnecting = fmt.Sprintf("Connecting to %s port %s", request["host"], request["port"])

	} else {
		logConnecting = fmt.Sprintf(
			"Connecting to %s port %s -> %s port %s", proxyHostPort[0], proxyHostPort[1], request["host"], request["port"],
		)
	}

	if i.Config.ShowLog {
		liblog.LogInfo(logConnecting, "INFO", liblog.Colors["G1"])
	}

	liblog.LogReplace(logConnecting, liblog.Colors["G2"])

	return net.DialTimeout("tcp", strings.Join(proxyHostPort, ":"), time.Duration(i.Config.Timeout)*time.Second)
}

func (i *Inject) DecodePayload(request ClientRequest) {
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[real_raw]", "[raw][crlf][crlf]")
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[raw]", "[method] [host_port] [protocol]")
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[method]", request["method"])
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[host_port]", "[host]:[port]")
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[host]", request["host"])
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[port]", request["port"])
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[protocol]", request["protocol"])
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[crlf]", "[cr][lf]")
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[lfcr]", "[lf][cr]")
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[cr]", "\r")
	i.Config.Payload = strings.ReplaceAll(i.Config.Payload, "[lf]", "\n")
}

func (i *Inject) TunnelType0(c net.Conn, request ClientRequest) {
	s, err := i.ProxyConnect(request)
	if err != nil {
		return
	}
	defer s.Close()

	if s.RemoteAddr().String() != request["host"]+":"+request["port"] {
		i.DecodePayload(request)
		s.Write([]byte(i.Config.Payload))
		if strings.Contains(strings.Split(i.ReadResponse(s), "\r\n")[0], "200") {
			//
		}
	}

	i.Handler(c, s)
}

func (i *Inject) TunnelType1(c net.Conn, request ClientRequest) {
	// TODO: SSL

	/**
	proxyAddress, err := i.GetProxy(request)
	if err != nil {
		fmt.Println(err)
		return
	}

	println("connect", strings.Join(proxyAddress, ":"))

	s, err := tls.Dial("tcp", strings.Join(proxyAddress, ":"), &tls.Config{
		ServerName:         i.Config.ServerNameIndication,
		InsecureSkipVerify: true,
	})
	if err != nil {
		fmt.Printf("%v - %v\n", s, err)
		return
	}
	defer s.Close()

	s.Handshake()

	println("test")

	i.Handler(c, s)
	**/
}

func (i *Inject) TunnelType2(c net.Conn, request ClientRequest) {
	s, err := i.ProxyConnect(request)
	if err != nil {
		return
	}
	defer s.Close()

	i.Handler(c, s)
}

func (i *Inject) Handler(c net.Conn, s net.Conn) {
	c.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

	done := make(chan bool)

	go i.Handle(s, c, done)
	go i.Handle(c, s, done)

	<-done
}

func (i *Inject) Handle(w io.Writer, r io.Reader, done chan bool) {
	io.Copy(w, r)

	done <- true
}
