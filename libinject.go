package libinject

import (
    "os"
    "io"
    "fmt"
    "net"
    "time"
    "errors"
    "strings"

    "github.com/aztecrabbit/liblog"
    "github.com/aztecrabbit/libredsocks"
)

var (
    Loop = true
    DefaultConfig = &Config{
        Type: 2,
        Port: "8989",
        Rules: map[string][]string{
        	"*:*": []string{
                "202.152.240.50:80",
            },
        },
        ProxyPayload: "[raw][crlf]Host: t.co[crlf]Host: [crlf][crlf]",
        ProxyTimeout: 5,
        ShowLog: false,
    }
)

type Config struct {
    Type int
    Port string
    Rules map[string][]string
    ProxyPayload string
    ProxyTimeout int
    ShowLog bool
}

type Inject struct {
    Config *Config
    Redsocks *libredsocks.Redsocks
}

func (i *Inject) Start() {
    inject, err := net.Listen("tcp", "0.0.0.0:" + i.Config.Port)
    if err != nil {
        liblog.LogException(err, "INFO")
        os.Exit(0)
    }

    for {
        client, err := inject.Accept()
        if err != nil {
            panic(err)
        }

        go  i.Forward(client)
    }
}

func (i *Inject) ExtractClientRequest(c net.Conn) (map[string]string, error) {
    buffer := make([]byte, 65535)
    length, _ := c.Read(buffer)

    request := make(map[string]string)
    payload := strings.Split(string(buffer[:length]), "\r\n")
    payloadHeader1 := strings.Split(payload[0], " ")

    if len(payloadHeader1) < 3 {
		return nil, errors.New("payload header 1 empty")
    }

    request["method"] = payloadHeader1[0]
    if request["method"] != "CONNECT" {
        return nil, errors.New("method not allowed!")
    }

    payloadHostPort := strings.Split(payloadHeader1[1], ":")
    request["host"] = payloadHostPort[0]
    request["port"] = payloadHostPort[1]

   	request["protocol"] = payloadHeader1[2]

    return request, nil
}

func (i *Inject) Forward(c net.Conn) {
    defer c.Close()

    request, err := i.ExtractClientRequest(c)
    if err != nil {
    	return
    }

    switch i.Config.Type {
        case 2:
            i.TunnelType2(c, request)
        case 3:
            i.TunnelType3(c, request)
        default:
            liblog.LogInfo("Inject type not found!", "INFO", liblog.Colors["R1"])
    }
}

func (i *Inject) GetProxy(request map[string]string) ([]string, error) {
    for whitelist, proxyHostPortList := range i.Config.Rules {
        whitelistHostPort := strings.Split(whitelist, ":")
        switch len(whitelistHostPort) {
            case 0:
                continue
            case 1:
                whitelistHostPort = append(whitelistHostPort, "80")
        }
        if (whitelistHostPort[0] == "*" || strings.Contains(request["host"], whitelistHostPort[0])) &&
                (whitelistHostPort[1] == "*" || whitelistHostPort[1] == request["port"]) {
            if len(proxyHostPortList) == 0 {
                continue
            }
            proxyHostPort := strings.Split(proxyHostPortList[0], ":")
            switch len(proxyHostPort) {
                case 0:
                    continue
                case 1:
                    proxyHostPort = append(proxyHostPort, "80")
            }
            if len(proxyHostPortList) > 1 {
                i.Config.Rules[whitelist] = append(proxyHostPortList[1:], proxyHostPortList[0])
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

    liblog.LogReplace(fmt.Sprintf(
            "Connecting to %s port %s -> %s port %s", proxyHostPort[0], proxyHostPort[1], request["host"], request["port"],
        ),
        liblog.Colors["G2"],
    )

    return net.DialTimeout("tcp", strings.Join(proxyHostPort, ":"), time.Duration(i.Config.ProxyTimeout) * time.Second)
}

func (i *Inject) TunnelType2(c net.Conn, request map[string]string) {
    s, err := i.ProxyConnect(request)
    if err != nil {
        return
    }
    defer s.Close()

    logConnectingMessage := "Connecting to " + request["host"] + " port " + request["port"]

    if i.Config.ShowLog {
        liblog.LogInfo(logConnectingMessage, "INFO", liblog.Colors["G1"])
    }

    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[real_raw]", "[raw][crlf][crlf]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[raw]", "[method] [host_port] [protocol]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[method]", request["method"])
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[host_port]", "[host]:[port]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[host]", request["host"])
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[port]", request["port"])
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[protocol]", request["protocol"])
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[crlf]", "[cr][lf]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[lfcr]", "[lf][cr]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[cr]", "\r")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[lf]", "\n")

    s.Write([]byte(i.Config.ProxyPayload))

    i.Handler(c, s)
}

func (i *Inject) TunnelType3(c net.Conn, request map[string]string) {
    s, err := i.ProxyConnect(request)
    if err != nil {
        return
    }
    defer s.Close()

    i.Handler(c, s)
}

func (i *Inject) Handler(c net.Conn, s net.Conn) {
    c.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

    time.Sleep(200 * time.Millisecond)

    done := make(chan bool)

    go i.Handle(s, c, done)
    go i.Handle(c, s, done)

    <- done
}

func (i *Inject) Handle(w io.Writer, r io.Reader, done chan bool) {
    io.Copy(w, r)

    done <- true
}
