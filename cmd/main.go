package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	kvstring "github.com/ctsc-bc/DApplication/internal"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	abci "github.com/tendermint/tendermint/abci/types"
	cfg "github.com/tendermint/tendermint/config"
	tmflags "github.com/tendermint/tendermint/libs/cli/flags"
	"github.com/tendermint/tendermint/libs/log"
	nm "github.com/tendermint/tendermint/node"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/proxy"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
)

var configFile string
var rootPath string

func init() {
	rootPath = os.Getenv("HOME") + "/.tendermint"
	if os.Getenv("TMHOME") != "" {
		rootPath = os.Getenv("TMHOME")
	} else {
		os.Setenv("TMHOME", rootPath)
	}
	flag.StringVar(&configFile, "config", rootPath+"/config/config.toml", "Path to config.toml")
}

func main() {

	app := kvstring.NewKVStringApplication(os.Getenv("HOME") + "/.tendermint/dapp")

	flag.Parse()

	node, err := newTendermint(app, configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(2)
	}

	node.Start()
	defer func() {
		node.Stop()
		node.Wait()
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	os.Exit(0)
}

func initFilesWithConfig(config *cfg.Config) error {
	// private validator
	privValKeyFile := config.PrivValidatorKeyFile()
	privValStateFile := config.PrivValidatorStateFile()
	var pv *privval.FilePV
	if kvstring.FileExists(privValKeyFile) {
		pv = privval.LoadFilePV(privValKeyFile, privValStateFile)
		//logger.Info("Found private validator", "keyFile", privValKeyFile,
		//	"stateFile", privValStateFile)
	} else {
		pv = privval.GenFilePV(privValKeyFile, privValStateFile)
		pv.Save()
		// logger.Info("Generated private validator", "keyFile", privValKeyFile,
		// 	"stateFile", privValStateFile)
	}

	nodeKeyFile := config.NodeKeyFile()
	if kvstring.FileExists(nodeKeyFile) {
		//logger.Info("Found node key", "path", nodeKeyFile)
	} else {
		if _, err := p2p.LoadOrGenNodeKey(nodeKeyFile); err != nil {
			return err
		}
		//logger.Info("Generated node key", "path", nodeKeyFile)
	}

	// genesis file
	genFile := config.GenesisFile()
	if kvstring.FileExists(genFile) {
		//logger.Info("Found genesis file", "path", genFile)
	} else {
		genDoc := types.GenesisDoc{
			ChainID:         fmt.Sprintf("9d-chain-%v", kvstring.Str(6)),
			GenesisTime:     tmtime.Now(),
			ConsensusParams: types.DefaultConsensusParams(),
		}
		key := pv.GetPubKey()
		genDoc.Validators = []types.GenesisValidator{{
			Address: key.Address(),
			PubKey:  key,
			Power:   10,
		}}

		if err := genDoc.SaveAs(genFile); err != nil {
			return err
		}
		//logger.Info("Generated genesis file", "path", genFile)
	}

	return nil
}

func newTendermint(app abci.Application, configFile string) (*nm.Node, error) {
	// read config
	config := cfg.DefaultConfig()
	config.SetRoot(rootPath)
	config.Consensus.CreateEmptyBlocks = false
	config.RootDir = filepath.Dir(filepath.Dir(configFile))
	if kvstring.EnsureDir(config.RootDir+"/config", 0700) != nil {
		fmt.Printf(config.RootDir + "error not found")
	}
	kvstring.EnsureDir(config.RootDir+"/data", 0700)
	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		//return nil, errors.Wrap(err, "viper failed to read config file")
		fmt.Printf("can not found configure file [" + configFile + "]\n")
		initFilesWithConfig(config)
		viper.ReadInConfig()
	}

	if err := viper.Unmarshal(config); err != nil {
		return nil, errors.Wrap(err, "viper failed to unmarshal config")
	}
	if err := config.ValidateBasic(); err != nil {
		return nil, errors.Wrap(err, "config is invalid")
	}

	// create logger
	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))
	var err error
	logger, err = tmflags.ParseLogLevel(config.LogLevel, logger, cfg.DefaultLogLevel())
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse log level")
	}

	// read private validator
	pv := privval.LoadFilePV(
		config.PrivValidatorKeyFile(),
		config.PrivValidatorStateFile(),
	)

	// read node key
	nodeKey, err := p2p.LoadNodeKey(config.NodeKeyFile())
	if err != nil {
		return nil, errors.Wrap(err, "failed to load node's key")
	}

	// create node
	node, err := nm.NewNode(
		config,
		pv,
		nodeKey,
		proxy.NewLocalClientCreator(app),
		nm.DefaultGenesisDocProviderFunc(config),
		nm.DefaultDBProvider,
		nm.DefaultMetricsProvider(config.Instrumentation),
		logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new Tendermint node")
	}
	return node, nil
}
