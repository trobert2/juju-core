package main

import (
    "os"
    "fmt"
    "path/filepath"

    // "launchpad.net/juju-core/agent"
    "launchpad.net/juju-core/worker"
    // "launchpad.net/juju-core/worker/authenticationworker"
    "launchpad.net/juju-core/worker/charmrevisionworker"
    "launchpad.net/juju-core/worker/deployer"
    "launchpad.net/juju-core/worker/firewaller"
    workerlogger "launchpad.net/juju-core/worker/logger"
    // "launchpad.net/juju-core/worker/machineenvironmentworker"
    "launchpad.net/juju-core/worker/machiner"
    // "launchpad.net/juju-core/worker/rsyslog"
    "launchpad.net/juju-core/worker/upgrader"
    "launchpad.net/juju-core/state/api/params"
    // "launchpad.net/juju-core/provider"
    "launchpad.net/juju-core/worker/provisioner"
    "launchpad.net/juju-core/utils"
)

func (a *MachineAgent) initAgent() error {
    if err := os.Remove(jujuRun); err != nil && !os.IsNotExist(err) {
        return err
    }
    jujud := filepath.Join(a.Conf.dataDir, "tools", a.Tag(), "jujud.exe")
    return utils.CreateSymLink(jujuRun, jujud)
}

// APIWorker returns a Worker that connects to the API and starts any
// workers that need an API connection.
//
// If a state worker is necessary, APIWorker calls ensureStateWorker.
func (a *MachineAgent) APIWorker(ensureStateWorker func()) (worker.Worker, error) {
    agentConfig := a.Conf.config
    st, entity, err := openAPIState(agentConfig, a)
    if err != nil {
        return nil, err
    }
    reportOpenedAPI(st)
    for _, job := range entity.Jobs() {
        if job.NeedsState() {
            ensureStateWorker()
            break
        }
    }
    /*
    rsyslogMode := rsyslog.RsyslogModeForwarding
    for _, job := range entity.Jobs() {
        if job == params.JobManageEnviron {
            rsyslogMode = rsyslog.RsyslogModeAccumulate
            break
        }
    } */

    runner := newRunner(connectionIsFatal(st), moreImportant)

    // Run the upgrader and the upgrade-steps worker without waiting for the upgrade steps to complete.
    runner.StartWorker("upgrader", func() (worker.Worker, error) {
        return upgrader.NewUpgrader(st.Upgrader(), agentConfig), nil
    })
    runner.StartWorker("upgrade-steps", func() (worker.Worker, error) {
        return a.upgradeWorker(st, entity.Jobs()), nil
    })

    // All other workers must wait for the upgrade steps to complete before starting.
    a.startWorkerAfterUpgrade(runner, "machiner", func() (worker.Worker, error) {
        return machiner.NewMachiner(st.Machiner(), agentConfig), nil
    })
    a.startWorkerAfterUpgrade(runner, "logger", func() (worker.Worker, error) {
        return workerlogger.NewLogger(st.Logger(), agentConfig), nil
    })
    // TODO: gsamfira: Port machineenvironmentworker to windows. Proxy settings can be written
    // in the registry
    /* 
    a.startWorkerAfterUpgrade(runner, "machineenvironmentworker", func() (worker.Worker, error) {
        return machineenvironmentworker.NewMachineEnvironmentWorker(st.Environment(), agentConfig), nil
    }) */
    // gsamfira: No syslog support on windows (yet)
    /*
    a.startWorkerAfterUpgrade(runner, "rsyslog", func() (worker.Worker, error) {
        return newRsyslogConfigWorker(st.Rsyslog(), agentConfig, rsyslogMode)
    }) */

    // If not a local provider bootstrap machine, start the worker to manage SSH keys.

    // TODO: gsamfira: This will need to be ported at a later time to setup x509 keys for
    // WinRm
    /*
    providerType := agentConfig.Value(agent.ProviderType)
    if providerType != provider.Local || a.MachineId != bootstrapMachineId {
        a.startWorkerAfterUpgrade(runner, "authenticationworker", func() (worker.Worker, error) {
            return authenticationworker.NewWorker(st.KeyUpdater(), agentConfig), nil
        })
    } */

    // Perform the operations needed to set up hosting for containers.
    if err := a.setupContainerSupport(runner, st, entity); err != nil {
        return nil, fmt.Errorf("setting up container support: %v", err)
    }
    for _, job := range entity.Jobs() {
        switch job {
        case params.JobHostUnits:
            a.startWorkerAfterUpgrade(runner, "deployer", func() (worker.Worker, error) {
                apiDeployer := st.Deployer()
                context := newDeployContext(apiDeployer, agentConfig)
                return deployer.NewDeployer(apiDeployer, context), nil
            })
        case params.JobManageEnviron:
            a.startWorkerAfterUpgrade(runner, "environ-provisioner", func() (worker.Worker, error) {
                return provisioner.NewEnvironProvisioner(st.Provisioner(), agentConfig), nil
            })
            // TODO(axw) 2013-09-24 bug #1229506
            // Make another job to enable the firewaller. Not all environments
            // are capable of managing ports centrally.
            a.startWorkerAfterUpgrade(runner, "firewaller", func() (worker.Worker, error) {
                return firewaller.NewFirewaller(st.Firewaller())
            })
            a.startWorkerAfterUpgrade(runner, "charm-revision-updater", func() (worker.Worker, error) {
                return charmrevisionworker.NewRevisionUpdateWorker(st.CharmRevisionUpdater()), nil
            })
        case params.JobManageStateDeprecated:
            // Legacy environments may set this, but we ignore it.
        default:
            // TODO(dimitern): Once all workers moved over to using
            // the API, report "unknown job type" here.
        }
    }
    return newCloseWorker(runner, st), nil // Note: a worker.Runner is itself a worker.Worker.
}