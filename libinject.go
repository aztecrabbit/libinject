package libinject

import (
    "os"
    "io"
    "fmt"
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

func (i *Inject) Forward(c net.Conn) {
    defer c.Close()

    s, err := net.DialTimeout("tcp", i.ProxyHost + ":" + i.ProxyPort, time.Duration(i.ProxyTimeout) * time.Second)
    if err != nil {
        log.Printf("%v", err)
        return
    }
    defer s.Close()

    buffer_size := make([]byte, 65535)
    length, _ := c.Read(buffer_size)

    if i.LogConnecting {
        client_payload := string(buffer_size[:length])
        client_payload_line_1 := strings.Split(client_payload, "\n")[0]
        client_payload_host_port := strings.Split(client_payload_line_1, " ")[1]
        client_payload_host_port_split := strings.Split(client_payload_host_port, ":")
        i.LogInfo("Connecting -> " + client_payload_host_port_split[0] + " port " + client_payload_host_port_split[1])
    }

    c.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
    s.Write([]byte(i.ProxyPayload))

    time.Sleep(200 * time.Millisecond)

    go io.Copy(s, c)
    io.Copy(c, s)
}

func (i *Inject) Start() {
    inject, err := net.Listen("tcp", "0.0.0.0:" + i.Port)
    if err != nil {
        liblog.LogInfo(fmt.Sprintf("Exception\n\n|   %v\n|\n", err), "INFO", liblog.Colors["R1"])
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
