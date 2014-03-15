package utils

import (
    "net"
    "os"
    "error"
    "strconv"
)


func TestPort(port int) error {
    p := fmt.Sprintf("127.0.0.1:%s", strconv.Itoa(port))
    conn, err := net.Dial("tcp", p)
    if err != nil {
        return err
    }
    defer conn.Close()
    return nil
}

func GetPort() (string, error) {
    port := 65000
    // test TCP connect on that port. If an error is returned
    // the port is free and can be used
    err := TestPort(port)
    if err == nil {
        for i:=65001; i<65535; i++ {
            port = i
            err = TestPort(port)
            if err != nil {
                port = i
                break
            }
        }
    }
    if err == nil {
        return "", errors.New("Failed to get free port")
    }
    return strconv.Itoa(port), nil
}

//TODO: get rid of this once named pipes are in
//This actually writes a text file on disk with the port nr
//assigned to the unit agent. 
func WriteSocketFile(socketPath string) (string, error){
    port, perr := GetPort()
    if perr != nil {
        return "", perr
    }

    if _, err := os.Stat(socketPath); err == nil {
        os.Remove(socketPath)
    }

    fd, err := os.Create(socketPath)
    if err != nil {
        return "", err
    }
    defer fd.Close()

    addr := fmt.Sprintf("127.0.0.1:%v", port)
    data := []byte(addr)

    _, ferr := f.Write(data)
    if ferr != nil {
        return "", ferr
    }
    return addr, nil
}