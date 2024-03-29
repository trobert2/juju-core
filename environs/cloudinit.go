// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package environs

import (
	"fmt"
	"path"

	"github.com/errgo/errgo"

	"launchpad.net/juju-core/agent"
	coreCloudinit "launchpad.net/juju-core/cloudinit"
	"launchpad.net/juju-core/constraints"
	"launchpad.net/juju-core/environs/cloudinit"
	"launchpad.net/juju-core/environs/config"
	"launchpad.net/juju-core/juju/osenv"
	"launchpad.net/juju-core/names"
	"launchpad.net/juju-core/state"
	"launchpad.net/juju-core/state/api"
	"launchpad.net/juju-core/state/api/params"
	"launchpad.net/juju-core/utils"
)

// DataDir is the default data directory.
// Tests can override this where needed, so they don't need to mess with global
// system state.
var DataDir = path.Join(osenv.LibDir, "juju")

// CloudInitOutputLog is the default cloud-init-output.log file path.
var CloudInitOutputLog = path.Join(osenv.LogDir, "cloud-init-output.log")

// MongoServiceName is the default Upstart service name for Mongo.
const MongoServiceName = "juju-db"

// NewMachineConfig sets up a basic machine configuration, for a non-bootstrap
// node.  You'll still need to supply more information, but this takes care of
// the fixed entries and the ones that are always needed.
func NewMachineConfig(machineID, machineNonce string, machineSeries string,
	stateInfo *state.Info, apiInfo *api.Info) *cloudinit.MachineConfig {

	localDataDir := DataDir
	localLogDir := agent.DefaultLogDir
	if len(machineSeries) > 3 && machineSeries[:3] == "win"{
		localDataDir = osenv.WinDataDir
		localLogDir = osenv.WinLogDir
	}
	return &cloudinit.MachineConfig{
		// Fixed entries.
		DataDir:                 localDataDir,
		LogDir:                  localLogDir,
		Jobs:                    []params.MachineJob{params.JobHostUnits},
		CloudInitOutputLog:      CloudInitOutputLog,
		MachineAgentServiceName: "jujud-" + names.MachineTag(machineID),
		MongoServiceName:        MongoServiceName,

		// Parameter entries.
		MachineId:    machineID,
		MachineNonce: machineNonce,
		StateInfo:    stateInfo,
		APIInfo:      apiInfo,
	}
}

// NewBootstrapMachineConfig sets up a basic machine configuration for a
// bootstrap node.  You'll still need to supply more information, but this
// takes care of the fixed entries and the ones that are always needed.
// stateInfoURL is the storage URL for the environment's state file.
func NewBootstrapMachineConfig(stateInfoURL string, privateSystemSSHKey string) *cloudinit.MachineConfig {
	// For a bootstrap instance, FinishMachineConfig will provide the
	// state.Info and the api.Info. The machine id must *always* be "0".
	mcfg := NewMachineConfig("0", state.BootstrapNonce, "", nil, nil)
	mcfg.StateServer = true
	mcfg.StateInfoURL = stateInfoURL
	mcfg.SystemPrivateSSHKey = privateSystemSSHKey
	mcfg.Jobs = []params.MachineJob{params.JobManageEnviron, params.JobHostUnits}
	return mcfg
}

// PopulateMachineConfig is called both from the FinishMachineConfig below,
// which does have access to the environment config, and from the container
// provisioners, which don't have access to the environment config. Everything
// that is needed to provision a container needs to be returned to the
// provisioner in the ContainerConfig structure. Those values are then used to
// call this function.
func PopulateMachineConfig(mcfg *cloudinit.MachineConfig,
	providerType, authorizedKeys string,
	sslHostnameVerification bool,
	proxy, aptProxy osenv.ProxySettings,
) error {
	if authorizedKeys == "" {
		return fmt.Errorf("environment configuration has no authorized-keys")
	}
	mcfg.AuthorizedKeys = authorizedKeys
	if mcfg.AgentEnvironment == nil {
		mcfg.AgentEnvironment = make(map[string]string)
	}
	mcfg.AgentEnvironment[agent.ProviderType] = providerType
	mcfg.AgentEnvironment[agent.ContainerType] = string(mcfg.MachineContainerType)
	mcfg.DisableSSLHostnameVerification = !sslHostnameVerification
	mcfg.ProxySettings = proxy
	mcfg.AptProxySettings = aptProxy
	return nil
}

// FinishMachineConfig sets fields on a MachineConfig that can be determined by
// inspecting a plain config.Config and the machine constraints at the last
// moment before bootstrapping. It assumes that the supplied Config comes from
// an environment that has passed through all the validation checks in the
// Bootstrap func, and that has set an agent-version (via finding the tools to,
// use for bootstrap, or otherwise).
// TODO(fwereade) This function is not meant to be "good" in any serious way:
// it is better that this functionality be collected in one place here than
// that it be spread out across 3 or 4 providers, but this is its only
// redeeming feature.
func FinishMachineConfig(mcfg *cloudinit.MachineConfig, cfg *config.Config, cons constraints.Value) (err error) {
	defer utils.ErrorContextf(&err, "cannot complete machine configuration")

	if err := PopulateMachineConfig(
		mcfg,
		cfg.Type(),
		cfg.AuthorizedKeys(),
		cfg.SSLHostnameVerification(),
		cfg.ProxySettings(),
		cfg.AptProxySettings(),
	); err != nil {
		return err
	}

	// The following settings are only appropriate at bootstrap time. At the
	// moment, the only state server is the bootstrap node, but this
	// will probably change.
	if !mcfg.StateServer {
		return nil
	}
	if mcfg.APIInfo != nil || mcfg.StateInfo != nil {
		return fmt.Errorf("machine configuration already has api/state info")
	}
	caCert, hasCACert := cfg.CACert()
	if !hasCACert {
		return fmt.Errorf("environment configuration has no ca-cert")
	}
	password := cfg.AdminSecret()
	if password == "" {
		return fmt.Errorf("environment configuration has no admin-secret")
	}
	passwordHash := utils.UserPasswordHash(password, utils.CompatSalt)
	mcfg.APIInfo = &api.Info{Password: passwordHash, CACert: caCert}
	mcfg.StateInfo = &state.Info{Password: passwordHash, CACert: caCert}
	mcfg.StatePort = cfg.StatePort()
	mcfg.APIPort = cfg.APIPort()
	mcfg.Constraints = cons
	if mcfg.Config, err = BootstrapConfig(cfg); err != nil {
		return err
	}

	// These really are directly relevant to running a state server.
	cert, key, err := cfg.GenerateStateServerCertAndKey()
	if err != nil {
		return errgo.Annotate(err, "cannot generate state server certificate")
	}
	mcfg.StateServerCert = cert
	mcfg.StateServerKey = key
	return nil
}

// ComposeUserData puts together a binary (gzipped) blob of user data.
// The additionalScripts are additional command lines that you need cloudinit
// to run on the instance; they are executed before all other cloud-init
// runcmds.  Use with care.
func ComposeUserData(cfg *cloudinit.MachineConfig, additionalScripts ...string) ([]byte, error) {
	cloudcfg := coreCloudinit.New()
	for _, script := range additionalScripts {
		if cfg.Tools.Version.Series[:3] == "win"{
			cloudcfg.AddPSCmd(script)
		}else{
			cloudcfg.AddRunCmd(script)
		}
	}
	// When bootstrapping, we only want to apt-get update/upgrade
	// and setup the SSH keys. The rest we leave to cloudinit/sshinit.
	if cfg.StateServer {
		if err := cloudinit.ConfigureBasic(cfg, cloudcfg); err != nil {
			return nil, err
		}
	} else {
		if err := cloudinit.Configure(cfg, cloudcfg); err != nil {
			return nil, err
		}
	}
	var data []byte
	var err error
	if cfg.Tools.Version.Series[:3] == "win"{
		data, err = cloudcfg.RenderWin()
	}else{
		data, err = cloudcfg.Render()
	}
	logger.Tracef("Generated cloud init:\n%s", string(data))
	if err != nil {
		return nil, err
	}
	return utils.Gzip(data), nil
}
