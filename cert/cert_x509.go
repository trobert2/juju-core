package cert

import (
    "crypto/rand"
    "io"
    "fmt"
    "os"
    "launchpad.net/juju-core/utils/exec"
)

func randomID() (string, error){
    b := make([]byte, 2)
    _, err := io.ReadFull(rand.Reader, b)
    if err != nil{
        return "", err
    }
    uuid := fmt.Sprintf("%x", b[0:])
    return uuid, nil
}

func Createx509Certificate(password string) (thumbprint, subject string){
    s, _ := randomID()
    username := "username-" + s
    upn := username + "@localhost"
    subject = "/CN=" + username

    os.Mkdir("working_directory", 0777)
    h, err := os.Create("working_directory/openssl_config.conf")
    if err != nil {
        fmt.Println(err)
    }

    conf := `distinguished_name  = req_distinguished_name
[req_distinguished_name]
[v3_req_client]
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:` + upn
    buf := []byte(conf)
    h.Write(buf)
    h.Close()

    os.Setenv("OPENSSL_CONF", "working_directory/openssl_config.conf")

    var com exec.RunParams

    com.Commands = `openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -out cert.pem -outform PEM -keyout working_directory/cert.key -subj `+ subject + ` -extensions v3_req_client`
    resp, err := exec.RunCommands(com)
    if err != nil {
        fmt.Println(err)
    }else if resp.Code != 0{
        fmt.Println("Error code:", resp.Code)
    }


    com.Commands = `openssl pkcs12 -export -in cert.pem -inkey working_directory/cert.key -out cert.pfx -password pass:` + password
    resp, err = exec.RunCommands(com)
    if err != nil {
        fmt.Println(err)
    }else if resp.Code != 0{
        fmt.Println("Error code:", resp.Code)
    }

    os.Remove(`rm working_directory/openssl_config.conf`)
    os.RemoveAll("working_directory")

    com.Commands = `openssl x509 -inform PEM -in cert.pem -fingerprint -noout | sed -e 's/\://g' | sed -n 's/^.*=\(.*\)$/\1/p'`
    resp, err = exec.RunCommands(com)
    if err != nil {
        fmt.Println(err)
    }else if resp.Code != 0{
        fmt.Println("Error code:", resp.Code)
    }
    no := len(resp.Stdout)
    thumbprint = string(resp.Stdout[:no])
    fmt.Println(thumbprint)
    subject = "CN=" + username
    return
}
