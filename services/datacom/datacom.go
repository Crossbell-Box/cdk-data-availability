package datacom

import (
	"context"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common"

	"github.com/0xPolygon/cdk-data-availability/rpc"
	"github.com/0xPolygon/cdk-data-availability/types"
	"github.com/jackc/pgx/v4"
)

// APIDATACOM is the namespace of the datacom service
const APIDATACOM = "datacom"

// DataComEndpoints contains implementations for the "datacom" RPC endpoints
type DataComEndpoints struct {
	db          DBInterface
	txMan       rpc.DBTxManager
	privateKey  *ecdsa.PrivateKey
	batcherAddr common.Address
}

// NewDataComEndpoints returns DataComEndpoints
func NewDataComEndpoints(
	db DBInterface, privateKey *ecdsa.PrivateKey, batcherAddr string,
) *DataComEndpoints {
	return &DataComEndpoints{
		db:          db,
		privateKey:  privateKey,
		batcherAddr: common.HexToAddress(batcherAddr),
	}
}

// SignSequence generates the accumulated input hash aka accInputHash of the sequence and sign it.
// After storing the data that will be sent hashed to the contract, it returns the signature.
// This endpoint is only accessible to the sequencer
func (d *DataComEndpoints) SignSequence(signedSequence types.SignedSequence) (interface{}, rpc.Error) {
	// Verify that the request comes from the sequencer
	sender, err := signedSequence.Signer()
	if err != nil {
		return "0x0", rpc.NewRPCError(rpc.DefaultErrorCode, "failed to verify sender")
	}
	// sender must be BatcherAddress
	if sender != d.batcherAddr {
		return "0x0", rpc.NewRPCError(rpc.DefaultErrorCode, "unauthorized batcher, expected %v, got %v", d.batcherAddr, sender)
	}
	// Store off-chain data by hash (hash(L2Data): L2Data)
	_, err = d.txMan.NewDbTxScope(d.db, func(ctx context.Context, dbTx pgx.Tx) (interface{}, rpc.Error) {
		err := d.db.StoreOffChainData(ctx, signedSequence.Sequence.OffChainData(), dbTx)
		if err != nil {
			return "0x0", rpc.NewRPCError(rpc.DefaultErrorCode, "failed to store offchain data")
		}

		return nil, nil
	})
	if err != nil {
		return "0x0", rpc.NewRPCError(rpc.DefaultErrorCode, "failed to store offchain data")
	}
	// Sign
	signedSequenceByMe, err := signedSequence.Sequence.Sign(d.privateKey)
	if err != nil {
		return "0x0", rpc.NewRPCError(rpc.DefaultErrorCode, "failed to sign")
	}
	// Return signature
	return signedSequenceByMe.Signature, nil
}
