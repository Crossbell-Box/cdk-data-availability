package synchronizer

import (
	"math/rand"
	"sync"
	"time"

	"github.com/0xPolygon/cdk-data-availability/config"
	"github.com/0xPolygon/cdk-data-availability/db"
	"github.com/0xPolygon/cdk-data-availability/etherman"
	"github.com/0xPolygon/cdk-data-availability/log"
	"github.com/0xPolygon/cdk-data-availability/rpc"
	"github.com/0xPolygon/cdk-data-availability/types"
	"github.com/ethereum/go-ethereum/common"
)

const defaultBlockBatchSize = 32

// BatchSynchronizer watches for batch events, checks if they are "locally" stored, then retrieves and stores missing data
type BatchSynchronizer struct {
	client         *etherman.Etherman
	stop           chan struct{}
	retry          time.Duration
	blockBatchSize uint
	self           common.Address
	db             *db.DB
	committee      map[common.Address]etherman.DataCommitteeMember
	lock           sync.Mutex
}

// NewBatchSynchronizer creates the BatchSynchronizer
func NewBatchSynchronizer(
	cfg config.L1Config,
	self common.Address,
	db *db.DB,
	ethClient *etherman.Etherman,
) (*BatchSynchronizer, error) {
	if cfg.BlockBatchSize == 0 {
		log.Infof("block batch size is not set, setting to default %d", defaultBlockBatchSize)
		cfg.BlockBatchSize = defaultBlockBatchSize
	}
	synchronizer := &BatchSynchronizer{
		client:         ethClient,
		stop:           make(chan struct{}),
		retry:          cfg.RetryPeriod.Duration,
		blockBatchSize: cfg.BlockBatchSize,
		self:           self,
		db:             db,
	}
	return synchronizer, synchronizer.resolveCommittee()
}

func (bs *BatchSynchronizer) resolveCommittee() error {
	bs.lock.Lock()
	defer bs.lock.Unlock()

	committee := make(map[common.Address]etherman.DataCommitteeMember)
	current, err := bs.client.GetCurrentDataCommittee()
	if err != nil {
		return err
	}
	for _, member := range current.Members {
		if bs.self != member.Addr {
			committee[member.Addr] = member
		}
	}
	bs.committee = committee
	return nil
}

func (bs *BatchSynchronizer) resolve(key common.Hash) (types.OffChainData, error) {
	log.Debugf("resolving missing data for key %v", key.Hex())
	if len(bs.committee) == 0 {
		// committee is resolved again once all members are evicted. They can be evicted
		// for not having data, or their config being malformed
		err := bs.resolveCommittee()
		if err != nil {
			return types.OffChainData{}, err
		}
	}
	// pull out the members, iterating will change the map on error
	members := make([]etherman.DataCommitteeMember, len(bs.committee))
	for _, member := range bs.committee {
		members = append(members, member)
	}
	// iterate through them randomly until data is resolved
	for _, r := range rand.Perm(len(members)) {
		member := members[r]
		if member.URL == "" || member.Addr == common.HexToAddress("0x0") || member.Addr == bs.self {
			delete(bs.committee, member.Addr)
			continue // malformed committee, skip what is known to be wrong
		}
		log.Infof("trying DAC %s: %s", member.Addr.Hex(), member.URL)
		value, err := resolveWithMember(key, member)
		if err != nil {
			log.Warnf("error resolving, continuing: %v", err)
			delete(bs.committee, member.Addr)
			continue // did not have data or errored out
		}
		return value, nil
	}
	return types.OffChainData{}, rpc.NewRPCError(rpc.NotFoundErrorCode, "no data found for key %v", key)
}
