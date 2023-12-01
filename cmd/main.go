package main

import (
	"fmt"
	dataavailability "github.com/0xPolygon/cdk-data-availability"
	"github.com/0xPolygon/cdk-data-availability/config"
	"github.com/0xPolygon/cdk-data-availability/db"
	"github.com/0xPolygon/cdk-data-availability/log"
	"github.com/0xPolygon/cdk-data-availability/rpc"
	"github.com/0xPolygon/cdk-data-availability/services/datacom"
	"github.com/0xPolygon/cdk-data-availability/services/sync"
	"github.com/urfave/cli/v2"
	"os"
)

const appName = "cdk-data-availability"

var (
	configFileFlag = cli.StringFlag{
		Name:     config.FlagCfg,
		Aliases:  []string{"c"},
		Usage:    "Configuration `FILE`",
		Required: false,
	}
)

func main() {
	app := cli.NewApp()
	app.Name = appName
	app.Version = dataavailability.Version
	app.Commands = []*cli.Command{
		{
			Name:    "run",
			Aliases: []string{},
			Usage:   fmt.Sprintf("Run the %v", appName),
			Action:  start,
			Flags:   []cli.Flag{&configFileFlag},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

func start(cliCtx *cli.Context) error {
	// Load config
	c, err := config.Load(cliCtx)
	if err != nil {
		panic(err)
	}
	setupLog(c.Log)

	// Prepare DB
	pg, err := db.NewSQLDB(c.DB)
	if err != nil {
		log.Fatal(err)
	}
	if err := db.RunMigrationsUp(pg); err != nil {
		log.Fatal(err)
	}
	storage := db.New(pg)

	// Load private key
	pk, err := config.NewKeyFromKeystore(c.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Register services
	server := rpc.NewServer(
		c.RPC,
		[]rpc.Service{
			{
				Name:    sync.APISYNC,
				Service: sync.NewSyncEndpoints(storage),
			},
			{
				Name: datacom.APIDATACOM,
				Service: datacom.NewDataComEndpoints(
					storage,
					pk,
					c.L1.BatcherAddr,
				),
			},
		},
	)

	// Run!
	if err := server.Start(); err != nil {
		log.Fatal(err)
	}

	return nil
}

func setupLog(c log.Config) {
	log.Init(c)
}
