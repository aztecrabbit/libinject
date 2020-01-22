package libinject

import (
    "os"
    "io"
    "log"
    "net"
    "time"
    "strings"

    "github.com/aztecrabbit/liblog"
)

var (
    Loop = true
    ConfigDefault = &Config{
        Port: "8989",
        ProxyHost: "202.152.240.50",
        ProxyPort: "80",
        ProxyPayload: "[raw][crlf]Host: t.co[crlf]Host: [crlf][crlf]",
        ProxyTimeout: 10,
        ShowLog: false,
    }
)

type Config struct {
    Port string
    ProxyHost string
    ProxyPort string
    ProxyPayload string
    ProxyTimeout int
    ShowLog bool
}

type Inject struct {
    Config *Config
}

func (i *Inject) LogInfo(message string) {
    liblog.LogInfo(message, "INFO", liblog.Colors["G1"])
}

func (i *Inject) LogReplace(message string) {
    liblog.LogReplace(message, liblog.Colors["G2"])
}

func (i *Inject) Forward(c net.Conn) {
    defer c.Close()

    s, err := net.DialTimeout("tcp", i.Config.ProxyHost + ":" + i.Config.ProxyPort, time.Duration(i.Config.ProxyTimeout) * time.Second)
    if err != nil {
        liblog.LogException(err, "INFO")
        return
    }
    defer s.Close()

    buffer_size := make([]byte, 65535)
    length, err := c.Read(buffer_size)
    if err != nil {
        panic(err)
    }

    client_payload := string(buffer_size[:length])
    client_payload_line_1 := strings.Split(strings.Split(client_payload, "\r\n")[0], " ")
    client_payload_method := client_payload_line_1[0]
    client_payload_protocol := client_payload_line_1[2]
    client_payload_host_port := strings.Split(client_payload_line_1[1], ":")
    client_payload_host := client_payload_host_port[0]
    client_payload_port := client_payload_host_port[1]

    if client_payload_method != "CONNECT" {
        liblog.LogInfo("Method not allowed", "INFO", liblog.Colors["R1"])
        return
    }

    logConnectingMessage := "Connecting to " + client_payload_host + " port " + client_payload_port

    if i.Config.ShowLog {
        i.LogInfo(logConnectingMessage)
    } else {
        i.LogReplace(logConnectingMessage)
    }

    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[real_raw]", "[raw][crlf][crlf]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[raw]", "[method] [host_port] [protocol]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[method]", client_payload_method)
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[protocol]", client_payload_protocol)
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[host_port]", "[host]:[port]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[host]", client_payload_host)
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[port]", client_payload_port)
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[crlf]", "[cr][lf]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[lfcr]", "[lf][cr]")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[cr]", "\r")
    i.Config.ProxyPayload = strings.ReplaceAll(i.Config.ProxyPayload, "[lf]", "\n")

    c.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
    s.Write([]byte(i.Config.ProxyPayload))

    time.Sleep(200 * time.Millisecond)

    done := make(chan bool)

    go i.Handler(s, c, done)
    go i.Handler(c, s, done)

    <- done

    c.Close()
    s.Close()
}

func (i *Inject) Handler(w io.Writer, r io.Reader, done chan bool) {
    io.Copy(w, r)

    done <- true
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
            log.Fatalf("failed to accept listener %v", err)
        }

        go  i.Forward(client)
    }
}
