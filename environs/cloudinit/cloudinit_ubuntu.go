package cloudinit

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"launchpad.net/juju-core/cloudinit"
	"launchpad.net/juju-core/names"
	"launchpad.net/juju-core/utils/proxy"
)

func UbuntuConfigureBasic(cfg *MachineConfig, c *cloudinit.Config) error {
	c.AddScripts(
		"set -xe", // ensure we run all the scripts or abort.
	)
	c.AddSSHAuthorizedKeys(cfg.AuthorizedKeys)
	c.SetOutput(cloudinit.OutAll, "| tee -a "+cfg.CloudInitOutputLog, "")
	// Create a file in a well-defined location containing the machine's
	// nonce. The presence and contents of this file will be verified
	// during bootstrap.
	//
	// Note: this must be the last runcmd we do in ConfigureBasic, as
	// the presence of the nonce file is used to gate the remainder
	// of synchronous bootstrap.
	noncefile := path.Join(cfg.DataDir, NonceFile)
	c.AddFile(noncefile, cfg.MachineNonce, 0644)
	return nil
}

// ConfigureJuju updates the provided cloudinit.Config with configuration
// to initialise a Juju machine agent.
func UbuntuConfigureJuju(cfg *MachineConfig, c *cloudinit.Config) error {
	if err := verifyConfig(cfg); err != nil {
		return err
	}

	// Initialise progress reporting. We need to do separately for runcmd
	// and (possibly, below) for bootcmd, as they may be run in different
	// shell sessions.
	initProgressCmd := cloudinit.InitProgressCmd()
	c.AddRunCmd(initProgressCmd)

	// If we're doing synchronous bootstrap or manual provisioning, then
	// ConfigureBasic won't have been invoked; thus, the output log won't
	// have been set. We don't want to show the log to the user, so simply
	// append to the log file rather than teeing.
	if stdout, _ := c.Output(cloudinit.OutAll); stdout == "" {
		c.SetOutput(cloudinit.OutAll, ">> "+cfg.CloudInitOutputLog, "")
		c.AddBootCmd(initProgressCmd)
		c.AddBootCmd(cloudinit.LogProgressCmd("Logging to %s on remote host", cfg.CloudInitOutputLog))
	}

	if !cfg.DisablePackageCommands {
		AddAptCommands(cfg.AptProxySettings, c)
	}

	// Write out the normal proxy settings so that the settings are
	// sourced by bash, and ssh through that.
	c.AddScripts(
		// We look to see if the proxy line is there already as
		// the manual provider may have had it aleady. The ubuntu
		// user may not exist (local provider only).
		`([ ! -e /home/ubuntu/.profile ] || grep -q '.juju-proxy' /home/ubuntu/.profile) || ` +
			`printf '\n# Added by juju\n[ -f "$HOME/.juju-proxy" ] && . "$HOME/.juju-proxy"\n' >> /home/ubuntu/.profile`)
	if (cfg.ProxySettings != proxy.Settings{}) {
		exportedProxyEnv := cfg.ProxySettings.AsScriptEnvironment()
		c.AddScripts(strings.Split(exportedProxyEnv, "\n")...)
		c.AddScripts(
			fmt.Sprintf(
				`[ -e /home/ubuntu ] && (printf '%%s\n' %s > /home/ubuntu/.juju-proxy && chown ubuntu:ubuntu /home/ubuntu/.juju-proxy)`,
				shquote(cfg.ProxySettings.AsScriptEnvironment())))
	}

	// Make the lock dir and change the ownership of the lock dir itself to
	// ubuntu:ubuntu from root:root so the juju-run command run as the ubuntu
	// user is able to get access to the hook execution lock (like the uniter
	// itself does.)
	lockDir := path.Join(cfg.DataDir, "locks")
	c.AddScripts(
		fmt.Sprintf("mkdir -p %s", lockDir),
		// We only try to change ownership if there is an ubuntu user
		// defined, and we determine this by the existance of the home dir.
		fmt.Sprintf("[ -e /home/ubuntu ] && chown ubuntu:ubuntu %s", lockDir),
		fmt.Sprintf("mkdir -p %s", cfg.LogDir),
		fmt.Sprintf("chown syslog:adm %s", cfg.LogDir),
	)

	// Make a directory for the tools to live in, then fetch the
	// tools and unarchive them into it.
	var copyCmd string
	if strings.HasPrefix(cfg.Tools.URL, fileSchemePrefix) {
		copyCmd = fmt.Sprintf("cp %s $bin/tools.tar.gz", shquote(cfg.Tools.URL[len(fileSchemePrefix):]))
	} else {
		curlCommand := "curl -sSfw 'tools from %{url_effective} downloaded: HTTP %{http_code}; time %{time_total}s; size %{size_download} bytes; speed %{speed_download} bytes/s '"
		if cfg.DisableSSLHostnameVerification {
			curlCommand += " --insecure"
		}
		copyCmd = fmt.Sprintf("%s -o $bin/tools.tar.gz %s", curlCommand, shquote(cfg.Tools.URL))
		c.AddRunCmd(cloudinit.LogProgressCmd("Fetching tools: %s", copyCmd))
	}
	toolsJson, err := json.Marshal(cfg.Tools)
	if err != nil {
		return err
	}
	c.AddScripts(
		"bin="+shquote(cfg.jujuTools()),
		"mkdir -p $bin",
		copyCmd,
		fmt.Sprintf("sha256sum $bin/tools.tar.gz > $bin/juju%s.sha256", cfg.Tools.Version),
		fmt.Sprintf(`grep '%s' $bin/juju%s.sha256 || (echo "Tools checksum mismatch"; exit 1)`,
			cfg.Tools.SHA256, cfg.Tools.Version),
		fmt.Sprintf("tar zxf $bin/tools.tar.gz -C $bin"),
		fmt.Sprintf("rm $bin/tools.tar.gz && rm $bin/juju%s.sha256", cfg.Tools.Version),
		fmt.Sprintf("printf %%s %s > $bin/downloaded-tools.txt", shquote(string(toolsJson))),
	)

	// We add the machine agent's configuration info
	// before running bootstrap-state so that bootstrap-state
	// has a chance to rerwrite it to change the password.
	// It would be cleaner to change bootstrap-state to
	// be responsible for starting the machine agent itself,
	// but this would not be backwardly compatible.
	machineTag := names.MachineTag(cfg.MachineId)
	_, err = cfg.addAgentInfo(c, machineTag)
	if err != nil {
		return err
	}

	// Add the cloud archive cloud-tools pocket to apt sources
	// for series that need it. This gives us up-to-date LXC,
	// MongoDB, and other infrastructure.
	if !cfg.DisablePackageCommands {
		series := cfg.Tools.Version.Series
		MaybeAddCloudArchiveCloudTools(c, series)
	}

	if cfg.Bootstrap {
		cons := cfg.Constraints.String()
		if cons != "" {
			cons = " --constraints " + shquote(cons)
		}
		var hardware string
		if cfg.HardwareCharacteristics != nil {
			if hardware = cfg.HardwareCharacteristics.String(); hardware != "" {
				hardware = " --hardware " + shquote(hardware)
			}
		}
		c.AddRunCmd(cloudinit.LogProgressCmd("Bootstrapping Juju machine agent"))
		c.AddScripts(
			// The bootstrapping is always run with debug on.
			cfg.jujuTools() + "/jujud bootstrap-state" +
				" --data-dir " + shquote(cfg.DataDir) +
				" --env-config " + shquote(base64yaml(cfg.Config)) +
				" --instance-id " + shquote(string(cfg.InstanceId)) +
				hardware +
				cons +
				" --debug",
		)
	}

	return cfg.addMachineAgentToBoot(c, machineTag, cfg.MachineId)
}
