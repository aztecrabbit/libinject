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
)

type Inject struct {
    Port string
    ProxyHost string
    ProxyPort string
    ProxyPayload string
    ProxyTimeout int
    LogConnecting bool
}

func (i *Inject) LogInfo(message string) {
    liblog.LogInfo(message, "INFO", liblog.Colors["G1"])
}

func (i *Inject) LogReplace(message string) {
    liblog.LogReplace(message, liblog.Colors["G2"])
}

func (i *Inject) Forward(c net.Conn) {
    defer c.Close()

    s, err := net.DialTimeout("tcp", i.ProxyHost + ":" + i.ProxyPort, time.Duration(i.ProxyTimeout) * time.Second)
    if err != nil {
        log.Printf("%v", err)
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

    logConnectingMessage := "Connecting to " + client_payload_host + " port " + client_payload_port
    if i.LogConnecting {
        i.LogInfo(logConnectingMessage)
    } else {
        i.LogReplace(logConnectingMessage)
    }

    i.ProxyPayload = strings.ReplaceAll(i.ProxyPayload, "[method]", client_payload_method)
    i.ProxyPayload = strings.ReplaceAll(i.ProxyPayload, "[protocol]", client_payload_protocol)
    i.ProxyPayload = strings.ReplaceAll(i.ProxyPayload, "[host_port]", "[host]:[port]")
    i.ProxyPayload = strings.ReplaceAll(i.ProxyPayload, "[host]", client_payload_host)
    i.ProxyPayload = strings.ReplaceAll(i.ProxyPayload, "[port]", client_payload_port)
    i.ProxyPayload = strings.ReplaceAll(i.ProxyPayload, "[crlf]", "[cr][lf]")
    i.ProxyPayload = strings.ReplaceAll(i.ProxyPayload, "[lfcr]", "[lf][cr]")
    i.ProxyPayload = strings.ReplaceAll(i.ProxyPayload, "[cr]", "\r")
    i.ProxyPayload = strings.ReplaceAll(i.ProxyPayload, "[lf]", "\n")

    c.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
    s.Write([]byte(i.ProxyPayload))

    time.Sleep(200 * time.Millisecond)

    go io.Copy(s, c)
    io.Copy(c, s)
}

func (i *Inject) Start() {
    inject, err := net.Listen("tcp", "0.0.0.0:" + i.Port)
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
