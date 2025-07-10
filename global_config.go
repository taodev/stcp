package stcp

import (
	"sync"

	"github.com/taodev/pkg/defaults"
	"github.com/taodev/pkg/types"
)

type GlobalConfig struct {
	PrivateKey types.Binary            `json:"private_key"`
	PublicKey  types.Binary            `json:"public_key"`
	KnownHosts map[string]types.Binary `json:"known_hosts"`

	mutex sync.RWMutex
}

var gGlobalConfig GlobalConfig

func SetGlobal(filename string) error {
	return defaults.LoadYAML(filename, &gGlobalConfig)
}

func GetGlobal() *GlobalConfig {
	return &gGlobalConfig
}

func HostKey(host string) types.Binary {
	gGlobalConfig.mutex.RLock()
	defer gGlobalConfig.mutex.RUnlock()
	return gGlobalConfig.KnownHosts[host]
}

func PrivateKey() types.Binary {
	gGlobalConfig.mutex.RLock()
	defer gGlobalConfig.mutex.RUnlock()
	return gGlobalConfig.PrivateKey
}

func PublicKey() types.Binary {
	gGlobalConfig.mutex.RLock()
	defer gGlobalConfig.mutex.RUnlock()
	return gGlobalConfig.PublicKey
}

func init() {
	gGlobalConfig.KnownHosts = make(map[string]types.Binary)
}
