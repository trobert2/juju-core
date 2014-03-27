package service

import (
    "errors"
    "fmt"
    "strings"

    "github.com/juju/loggo"
    "launchpad.net/juju-core/utils/exec"
)

var logger = loggo.GetLogger("juju.worker.deployer.service_windows")

type Cmd struct {
    Service
    Description string
    ServiceBin  string
    Cmd         string
}

type Service struct {
    Name        string
}

// gets the service status
func (s *Service) Status() (string, error){
    logger.Infof("checking unit %q", s.Name)
    cmd := []string{
        "powershell",
        "Invoke-Command {",
        fmt.Sprintf(`$x = Get-Service "%s"`, s.Name),
        exec.CheckError,
        "$x.Status",
        "}",
    }
    out, err := exec.RunCommand(cmd)
    logger.Infof("checking unit %v --> %v", out, err)
    if err != nil {
        return "", err
    }
    return out, nil
}

func (s *Service) Running() bool{
    status, err := s.Status()
    logger.Infof("Service %q Status %q", s.Name, status)
    if err != nil {
        return false
    }
    if strings.TrimSpace(status) == "Stopped" {
        return false
    }
    return true
}

func (s *Service) Installed() bool {
    _, err := s.Status()
    if err == nil {
        return true
    }
    return false
}

func (s *Service) Start() error {
    logger.Infof("Starting service %q", s.Name)
    if s.Running() {
        logger.Infof("Service %q ALREADY RUNNING", s.Name)
        return nil
    }
    cmd := []string{
        "powershell",
        "Invoke-Command {",
        fmt.Sprintf(`Start-Service "%s"`, s.Name),
        exec.CheckError,
        "}",
    }
    _, err := exec.RunCommand(cmd)
    logger.Infof("--> Starting service %q", err)
    if err != nil {
        return err
    }
    return nil
}

func (s *Service) Stop() error {
    if !s.Running() {
        return nil
    }
    cmd := []string{
        "powershell",
        "Invoke-Command {",
        fmt.Sprintf(`Stop-Service "%s"`, s.Name),
        exec.CheckError,
        "}",
    }
    _, err := exec.RunCommand(cmd)
    if err != nil {
        return err
    }
    return nil
}

func (s *Service) Remove() error {
    _, err := s.Status()
    if err != nil {
        return err
    }
    cmd := []string{
        "powershell",
        "Invoke-Command {",
        fmt.Sprintf(`$x = gwmi win32_service -filter 'name="%s"'`, s.Name),
        exec.CheckError,
        "$x.Delete()",
        exec.CheckError,
        "}",
    }
    _, errCmd := exec.RunCommand(cmd)
    if errCmd != nil {
        return errCmd
    }
    return nil
}

func (c *Cmd) validate() error {
    if c.ServiceBin == "" {
        return errors.New("missing Service")
    }
    if c.Cmd == "" {
        return errors.New("missing Cmd")
    }
    if c.Description == "" {
        return errors.New("missing Description")
    }
    if c.Name == "" {
        return errors.New("missing Name")
    }
    return nil
}

func (c *Cmd) Install() error{
    err := c.validate()
    if err != nil {
        return err
    }
    if c.Service.Installed(){
        return errors.New(fmt.Sprintf("Service %s already installed", c.Service.Name))
    }
    serviceString := fmt.Sprintf(`"%s" "%s" %s`, c.ServiceBin, c.Service.Name, c.Cmd)
    cmd := []string{
        fmt.Sprintf("powershell"),
        fmt.Sprintf(`New-Service -Name '%s' -DisplayName '%s' '%s'`, c.Service.Name, c.Description, serviceString),
    }
    _, errCmd := exec.RunCommand(cmd)
    if errCmd != nil {
        return errCmd
    }
    return c.Service.Start()
}

func (s *Service) StopAndRemove() error {
    err := s.Stop()
    if err != nil {
        return err
    }
    return s.Remove()
}

func NewService(name string) *Service{
    return &Service{
        Name: name,
    }
}
