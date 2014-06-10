package cloudinit

import (
	"encoding/json"
	"fmt"
	"path"

	agenttools "launchpad.net/juju-core/agent/tools"
	"launchpad.net/juju-core/cloudinit"
	"launchpad.net/juju-core/juju/osenv"
	"launchpad.net/juju-core/names"
	"launchpad.net/juju-core/utils"
)

func WinConfigureBasic(cfg *MachineConfig, c *cloudinit.Config) error {
	zipUrl := "https://www.cloudbase.it/downloads/7z920-x64.msi"
	gitUrl := "https://www.cloudbase.it/downloads/Git-1.8.5.2-preview20131230.exe"
	var zipDst = path.Join(osenv.WinTempDir, "7z920-x64.msi")
	var gitDst = path.Join(osenv.WinTempDir, "Git-1.8.5.2-preview20131230.exe")

	c.AddPSScripts(
		fmt.Sprintf(`%s`, winPowershellHelperFunctions),
		fmt.Sprintf(`icacls "%s" /grant "jujud:(OI)(CI)(F)" /T`, utils.PathToWindows(osenv.WinBaseDir)),
		fmt.Sprintf(`mkdir %s`, utils.PathToWindows(osenv.WinTempDir)),
		fmt.Sprintf(`ExecRetry { (new-object System.Net.WebClient).DownloadFile("%s", "%s") }`,
			zipUrl, utils.PathToWindows(zipDst)),
		fmt.Sprintf(`cmd.exe /C call msiexec.exe /i "%s" /qb`, utils.PathToWindows(zipDst)),
		fmt.Sprintf(`if ($? -eq $false){ Throw "Failed to install 7zip" }`),
		fmt.Sprintf(`ExecRetry { (new-object System.Net.WebClient).DownloadFile("%s", "%s") }`,
			gitUrl, utils.PathToWindows(gitDst)),
		fmt.Sprintf(`cmd.exe /C call "%s" /SILENT`, utils.PathToWindows(gitDst)),
		fmt.Sprintf(`if ($? -eq $false){ Throw "Failed to install Git" }`),
		fmt.Sprintf(`mkdir "%s"`, utils.PathToWindows(osenv.WinBinDir)),
		fmt.Sprintf(`%s`, winSetPasswdScript),
		// fmt.Sprintf(`Start-Process -FilePath powershell.exe -LoadUserProfile -WorkingDirectory '/' -Wait -Credential $jujuCreds -ArgumentList "C:\juju\bin\save_pass.ps1 -pass $juju_passwd"`),
		fmt.Sprintf(`Start-ProcessAsUser -Command $powershell -Arguments "-File C:\juju\bin\save_pass.ps1 $juju_passwd" -Credential $jujuCreds`),
		fmt.Sprintf(`mkdir "%s\locks"`, utils.PathToWindows(osenv.WinLibDir)),
		fmt.Sprintf(`Start-ProcessAsUser -Command $cmdExe -Arguments '/C setx PATH "%%PATH%%;%%PROGRAMFILES(x86)%%\Git\cmd;C:\Juju\bin"' -Credential $jujuCreds`),
		// fmt.Sprintf(`Start-Process -FilePath cmd.exe -LoadUserProfile -WorkingDirectory '/' -Wait -Credential $jujuCreds -ArgumentList '/C call setx PATH "%%PATH%%;%%PROGRAMFILES(x86)%%\Git\cmd;C:\Juju\bin"'`),
	)
	noncefile := path.Join(cfg.DataDir, NonceFile)
	c.AddPSScripts(
		fmt.Sprintf(`Set-Content "%s" "%s"`, utils.PathToWindows(noncefile), shquote(cfg.MachineNonce)),
	)
	return nil
}

func WinConfigureJuju(cfg *MachineConfig, c *cloudinit.Config) error {
	if err := verifyConfig(cfg); err != nil {
		return err
	}
	toolsJson, err := json.Marshal(cfg.Tools)
	if err != nil {
		return err
	}
	var zipBin string = `C:\Program Files\7-Zip\7z.exe`
	c.AddPSScripts(
		fmt.Sprintf(`$binDir="%s"`, utils.PathToWindows(cfg.jujuTools())),
		fmt.Sprintf(`mkdir '%s\juju'`, utils.PathToWindows(cfg.LogDir)),
		fmt.Sprintf(`mkdir $binDir`),
		fmt.Sprintf(`$WebClient = New-Object System.Net.WebClient`),
		fmt.Sprintf(`[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}`),
		fmt.Sprintf(`ExecRetry { $WebClient.DownloadFile('%s', "$binDir\tools.tar.gz") }`, cfg.Tools.URL),
		fmt.Sprintf(`$dToolsHash = (Get-FileHash -Algorithm SHA256 "$binDir\tools.tar.gz").hash`),
		fmt.Sprintf(`$dToolsHash > "$binDir\juju%s.sha256"`,
			cfg.Tools.Version),
		fmt.Sprintf(`if ($dToolsHash.ToLower() -ne "%s"){ Throw "Tools checksum mismatch"}`,
			cfg.Tools.SHA256),
		fmt.Sprintf(`& "%s" x "$binDir\tools.tar.gz" -o"$binDir\"`, zipBin),
		fmt.Sprintf(`& "%s" x "$binDir\tools.tar" -o"$binDir\"`, zipBin),
		fmt.Sprintf(`rm "$binDir\tools.tar*"`),
		fmt.Sprintf(`Set-Content $binDir\downloaded-tools.txt '%s'`, string(toolsJson)),
	)

	machineTag := names.MachineTag(cfg.MachineId)
	_, err = cfg.addAgentInfo(c, machineTag)
	if err != nil {
		return err
	}
	return cfg.winAddMachineAgentToBoot(c, machineTag, cfg.MachineId)
}

// MachineAgentWindowsService returns the powershell command for a machine agent service
// based on the tag and machineId passed in.
// TODO: gsamfira: find a better place for this
func MachineAgentWindowsService(name, toolsDir, dataDir, logDir, tag, machineId string) []string {
	jujuServiceWrapper := path.Join(toolsDir, "JujuService.exe")
	logFile := path.Join(logDir, tag+".log")
	jujud := path.Join(toolsDir, "jujud.exe")

	serviceString := fmt.Sprintf(`"%s" "%s" "%s" machine --data-dir "%s" --machine-id "%s" --debug --log-file "%s"`,
		utils.PathToWindows(jujuServiceWrapper), name, utils.PathToWindows(jujud), utils.PathToWindows(dataDir), machineId, utils.PathToWindows(logFile))

	cmd := []string{
		fmt.Sprintf(`New-Service -Credential $jujuCreds -Name '%s' -DisplayName 'Jujud machine agent' '%s'`, name, serviceString),
		// fmt.Sprintf(`cmd.exe /C sc config %s start=delayed-auto`, name),
		fmt.Sprintf(`Start-Service %s`, name),
	}
	return cmd
}

func (cfg *MachineConfig) winAddMachineAgentToBoot(c *cloudinit.Config, tag, machineId string) error {
	// Make the agent run via a symbolic link to the actual tools
	// directory, so it can upgrade itself without needing to change
	// the upstart script.
	toolsDir := agenttools.ToolsDir(cfg.DataDir, tag)
	// TODO(dfc) ln -nfs, so it doesn't fail if for some reason that the target already exists
	c.AddPSScripts(fmt.Sprintf(`cmd.exe /C mklink %s %v`, utils.PathToWindows(toolsDir), cfg.Tools.Version))
	name := cfg.MachineAgentServiceName
	cmds := MachineAgentWindowsService(name, toolsDir, cfg.DataDir, cfg.LogDir, tag, machineId)
	c.AddPSScripts(cmds...)
	return nil
}
