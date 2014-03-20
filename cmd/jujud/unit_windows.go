package main

import (
    "launchpad.net/juju-core/worker"
    // "launchpad.net/juju-core/worker/rsyslog"
    "launchpad.net/juju-core/worker/uniter"
    "launchpad.net/juju-core/worker/upgrader"
    workerlogger "launchpad.net/juju-core/worker/logger"
)

func (a *UnitAgent) APIWorkers() (worker.Worker, error) {
    agentConfig := a.Conf.config
    st, entity, err := openAPIState(agentConfig, a)
    if err != nil {
        return nil, err
    }
    dataDir := a.Conf.dataDir
    runner := worker.NewRunner(connectionIsFatal(st), moreImportant)
    runner.StartWorker("upgrader", func() (worker.Worker, error) {
        return upgrader.NewUpgrader(st.Upgrader(), agentConfig), nil
    })
    runner.StartWorker("logger", func() (worker.Worker, error) {
        return workerlogger.NewLogger(st.Logger(), agentConfig), nil
    })
    runner.StartWorker("uniter", func() (worker.Worker, error) {
        return uniter.NewUniter(st.Uniter(), entity.Tag(), dataDir), nil
    })
    // runner.StartWorker("rsyslog", func() (worker.Worker, error) {
    //     return newRsyslogConfigWorker(st.Rsyslog(), agentConfig, rsyslog.RsyslogModeForwarding)
    // })
    return newCloseWorker(runner, st), nil
}