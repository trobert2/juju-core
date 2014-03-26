package authenticationworker

import (
	"strings"

	"github.com/juju/loggo"
	"launchpad.net/tomb"

	"launchpad.net/juju-core/agent"
	"launchpad.net/juju-core/log"
	"launchpad.net/juju-core/state/api/keyupdater"
	"launchpad.net/juju-core/state/api/watcher"
	"launchpad.net/juju-core/utils/exec"
	"launchpad.net/juju-core/utils/set"
	"launchpad.net/juju-core/utils/ssh"
	"launchpad.net/juju-core/utils/winrm"
	"launchpad.net/juju-core/worker"
)

type keyupdaterWorker struct {
	st   *keyupdater.State
	tomb tomb.Tomb
	tag  string
	Keys set.Strings
}

var WinRmUser = "ubuntu"
var logger = loggo.GetLogger("juju.worker.authenticationworker")


func NewWorker(st *keyupdater.State, agentConfig agent.Config) worker.Worker {
	kw := &keyupdaterWorker{st: st, tag: agentConfig.Tag()}
	return worker.NewNotifyWorker(kw)
}

func (kw *keyupdaterWorker) addX509Key(pemFile string) error {
	var par exec.RunParams
	com1 := `$cacert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("`+ pemFile +`"); `
	com2 := `$castore = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine); `
	com3 := `$castore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite); `
	com4 := `$castore.Add($cacert); `

	par.Commands = com1 + com2 + com3 + com4
	resp, _ := exec.RunCommands(par)
	n := len(resp.Stderr)
	if n > 0 {
		if string(resp.Stderr[62:104]) == "The system cannot find the file specified." {
			err = string(resp.Stderr[62:104])
		} else {
			err = string(resp.Stderr[:n])
		}
	}
	return
}

func (kw *keyupdaterWorker) removeX509Key(pemFile string) error {
	var par exec.RunParams
	com1 := `$cacert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("`+ pemFile +`"); `
	com2 := `$castore = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine); `
	com3 := `$castore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite); `
	com4 := `$castore.Remove($cacert); `

	par.Commands = com1 + com2 + com3 + com4
	resp, _ := exec.RunCommands(par)
	n := len(resp.Stderr)
	if n > 0 {
		if string(resp.Stderr[62:104]) == "The system cannot find the file specified." {
			err = string(resp.Stderr[62:104])
		} else {
			err = string(resp.Stderr[:n])
		}
	}
	return
}

func (kw *keyupdaterWorker) SetUp() (watcher.NotifyWatcher, error) {
	Keys, err := kw.st.X509Keys(kw.tag)
	if err != nil {
		return nil, log.LoggedErrorf(logger, "reading windows keys for %q: %v", kw.tag, err)
	}
	kw.Keys = set.NewStrings(Keys...)
	for _, key := range Keys {
		keyPath, err := winrm.WriteKey(key)
		if err != nil{
			return nil, log.LoggedErrorf(logger, "writting current windows keys: %v", err)
		}
		if err := kw.addX509Key(keyPath); err != nil {
			return nil, log.LoggedErrorf(logger, "adding current windows keys: %v", err)
		}
	}
	w, err := kw.st.WatchX509Keys(kw.tag)
	if err != nil {
		return nil, log.LoggedErrorf(logger, "starting key updater worker: %v", err)
	}
	logger.Infof("%q key updater worker started", kw.tag)
	return w, nil
}

func (kw *keyupdaterWorker) Handle() error {
	newKeys, err := kw.st.X509Keys(kw.tag)
	if err != nil {
		return log.LoggedErrorf(logger, "reading X509 Keys for %q: %v", kw.tag, err)
	}
	// Figure out if any keys have been added or deleted.
	latestKeys := set.NewStrings(newKeys...)
	deleted := kw.Keys.Difference(latestKeys)
	added := latestKeys.Difference(kw.Keys)
	if added.Size() > 0 {
		logger.Debugf("adding keys to authorised keys: %v", added)
		addedKeys := ssh.SplitAuthorisedKeys(added)
		for _, key := range addedKeys {
			keyPath, err := winrm.WriteKey(key)
			if err != nil{
				return nil, log.LoggedErrorf(logger, "writting current windows keys: %v", err)
			}
			if err := kw.addX509Key(keyPath); err != nil {
				return nil, log.LoggedErrorf(logger, "adding current windows keys: %v", err)
			}
	} else if deleted.Size() > 0 {
		logger.Debugf("deleting keys from authorised keys: %v", deleted)
		deletedKeys := ssh.SplitAuthorisedKeys(deleted)
		logger.Debugf("adding keys to authorised keys: %v", added)
		for _, key := range deletedKeys {
			keyPath, err := winrm.WriteKey(key)
			if err != nil{
				return nil, log.LoggedErrorf(logger, "writting current windows keys: %v", err)
			}
			if err := kw.removeX509Key(keyPath); err != nil {
				return nil, log.LoggedErrorf(logger, "adding current windows keys: %v", err)
			}
			os.Remove(keyPath)
	}
	kw.Keys = newKeys
	return nil
}

func (kw *keyupdaterWorker) TearDown() error {
	return nil
}