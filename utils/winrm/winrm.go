package winrm

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	"github.com/juju/loggo"

	"launchpad.net/juju-core/utils/exec"
)

var logger = loggo.GetLogger("juju.utils.winrm")

const (
	x509KeysDir  	   = "~%s/.winrm"
	x509KeysFile 	   = "windows_key.pem"
	Windowsx509KeysDir = `C:\winrmCertificates\`
)

func randomName() (string, error){
    b := make([]byte, 8)
    _, err := io.ReadFull(rand.Reader, b)
    if err != nil{
        return "", err
    }
    uuid := fmt.Sprintf("%x", b[0:])
    return uuid, nil
}

func fileExists(path string) (bool, error) {
    _, err := os.Stat(path)
    if err == nil { return true, nil }
    if os.IsNotExist(err) { return false, nil }
    return false, err
}

func getCertFolder(path string) {
	exists, _ := fileExists(path)
	fmt.Println(exists)
	if exists == false{
	    os.MkdirAll(path, 7777)
	}
}

func WriteKey(keyData string) (filePath string, err error) {
	getCertFolder(Windowsx509KeysDir)
	data := []byte(keyData)
	for true{
		name, err := randomName()
		if err != nil{
	        return "", err
	    }
	    checkPath := Windowsx509KeysDir + name + ".pem"
	    exists, _ := fileExists(checkPath)
	    if exists == true{
	    	continue
	    }
	    filePath = checkPath
	    break
	}
	ioutil.WriteFile(filePath, data, 7777)
    return filePath, nil
}

func GetThumbprint(certificate string) (thumb, err string) {
var par exec.RunParams
	par.Command = `openssl x509 -inform PEM -in ` + certificate + ` -fingerprint -noout | sed -e 's/\://g'`
	resp, _ := exec.RunCommands(par)
	n := len(resp.Stderr)
	if n > 0 {
			err = string(resp.Stderr[:n])
		} else {
			thumb = strings.Split(string(resp.Stdout), "=")[1]
		}
	return
}

func GetSubject(certificate string) (subject, err string) {
	var par exec.RunParams
	par.Command = `openssl x509 -inform PEM -in ` + certificate + ` -subject -noout`
	resp, _ := exec.RunCommands(par)
	n := len(resp.Stderr)
	if n > 0 {
			err = string(resp.Stderr[:n])
		} else {
			subject = strings.Split(string(resp.Stdout), "=")[2]
		}
	return
}