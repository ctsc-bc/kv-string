package kvstring

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/libs/kv"
	"github.com/tendermint/tendermint/libs/log"
	tmtypes "github.com/tendermint/tendermint/types"
	"github.com/tendermint/tendermint/version"
	dbm "github.com/tendermint/tm-db"
)

var (
	stateKey                         = []byte("stateKey")
	kvPairPrefixkey                  = []byte("kvPairKey:")
	ProtocolVersion version.Protocol = 0x1
)

type State struct {
	db      dbm.DB
	Size    int64  `json:"size"`
	Height  int64  `json:"height"`
	AppHash []byte `json:"app_hash"`
}

func loadState(db dbm.DB) State {
	stateBytes, _ := db.Get(stateKey)
	var state State
	if len(stateBytes) != 0 {
		err := json.Unmarshal(stateBytes, &state)
		if err != nil {
			panic(err)
		}
	}
	state.db = db
	return state
}

func saveState(state State) {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	state.db.Set(stateKey, stateBytes)
}

const (
	ValidatorSetChangePrefix string = "val:"
)

var _ types.Application = (*KVStringApplication)(nil)

type KVStringApplication struct {
	types.BaseApplication
	state              State
	ValUpdates         []types.ValidatorUpdate
	valAddrToPubKeyMap map[string]types.PubKey
	logger             log.Logger
}

func NewKVStringApplication(dbDir string) *KVStringApplication {
	name := "kvstring"
	db, err := dbm.NewGoLevelDB(name, dbDir)
	if err != nil {
		panic(err)
	}
	state := loadState(db)

	return &KVStringApplication{
		state:              state,
		valAddrToPubKeyMap: make(map[string]types.PubKey),
		logger:             log.NewNopLogger(),
	}
}

func prefixKey(key []byte) []byte {
	return append(kvPairPrefixkey, key...)
}

func (app *KVStringApplication) SetLogger(l log.Logger) {
	app.logger = l
}

func (app *KVStringApplication) Info(req types.RequestInfo) types.ResponseInfo {

	return types.ResponseInfo{
		Data:             fmt.Sprintf("{\"size\":%v}", app.state.Size),
		Version:          version.ABCIVersion,
		AppVersion:       ProtocolVersion.Uint64(),
		LastBlockHeight:  app.state.Height,
		LastBlockAppHash: app.state.AppHash,
	}
}

func (app *KVStringApplication) SetOption(req types.RequestSetOption) types.ResponseSetOption {
	return app.SetOption(req)
}

func isValidatorTx(tx []byte) bool {
	return strings.HasPrefix(string(tx), ValidatorSetChangePrefix)
}

func (app *KVStringApplication) DeliverTx(req types.RequestDeliverTx) types.ResponseDeliverTx {
	if isValidatorTx(req.Tx) {
		// update validators in the merkle tree
		// and in app.ValUpdates
		return app.execValidatorTx(req.Tx)
	}

	// parts := decodeValue(req.Tx)
	// if parts != nil {
	// 	if transaction(*app, parts) {
	// 		events := []types.Event{
	// 			{
	// 				Type: "app",
	// 				Attributes: []kv.Pair{
	// 					{Key: []byte("creator"), Value: []byte("Cosmoshi Netowoko")},
	// 					{Key: []byte("key"), Value: parts[0]},
	// 				},
	// 			},
	// 		}

	// 		return types.ResponseDeliverTx{Code: CodeTypeOK, Events: events}
	// 	}
	// }

	events := []types.Event{
		{
			Type: "app",
			Attributes: []kv.Pair{
				{Key: []byte("creator"), Value: []byte("Cosmoshi Netowoko")},
				{Key: []byte("key"), Value: []byte("test")},
			},
		},
	}

	return types.ResponseDeliverTx{Code: CodeTypeUnknownError, Events: events}
}

func (app *KVStringApplication) CheckTx(req types.RequestCheckTx) types.ResponseCheckTx {
	return types.ResponseCheckTx{Code: CodeTypeOK, GasWanted: 1}
}

func (app *KVStringApplication) Commit() types.ResponseCommit {
	// Using a memdb - just return the big endian size of the db
	appHash := make([]byte, 8)
	binary.PutVarint(appHash, app.state.Size)
	app.state.AppHash = appHash
	app.state.Height++
	saveState(app.state)
	return types.ResponseCommit{Data: appHash}
}

func (app *KVStringApplication) Query(reqQuery types.RequestQuery) (resQuery types.ResponseQuery) {
	switch reqQuery.Path {
	case "/val":
		key := []byte("val:" + string(reqQuery.Data))
		value, _ := app.state.db.Get(key)
		resQuery.Key = reqQuery.Data
		resQuery.Value = value
		return
	default:
		if reqQuery.Prove {
			value, _ := app.state.db.Get(prefixKey(reqQuery.Data))
			resQuery.Index = -1 // TODO make Proof return index
			resQuery.Key = reqQuery.Data
			resQuery.Value = value
			if value != nil {
				resQuery.Log = "exists"
			} else {
				resQuery.Log = "does not exist"
			}

			return
		}

		resQuery.Key = reqQuery.Data
		value, _ := app.state.db.Get(prefixKey(reqQuery.Data))
		resQuery.Value = value
		if value != nil {
			resQuery.Log = "exists"
		} else {
			resQuery.Log = "does not exist"
		}

		return
	}
}

func (app *KVStringApplication) InitChain(req types.RequestInitChain) types.ResponseInitChain {
	for _, v := range req.Validators {
		r := app.updateValidator(v)
		if r.IsErr() {
			app.logger.Error("Error updating validators", "r", r)
		}
	}
	return types.ResponseInitChain{}
}

func (app *KVStringApplication) BeginBlock(req types.RequestBeginBlock) types.ResponseBeginBlock {
	app.ValUpdates = make([]types.ValidatorUpdate, 0)
	// deal with malicious behavior
	for _, env := range req.ByzantineValidators {
		if env.Type == tmtypes.ABCIEvidenceTypeDuplicateVote {
			if env.TotalVotingPower == 0 {
				continue
			}
			app.updateValidator(types.ValidatorUpdate{
				PubKey: app.valAddrToPubKeyMap[string(env.Validator.Address)],
				Power:  env.TotalVotingPower - 1,
			})
		}
	}
	return types.ResponseBeginBlock{}
}

func (app *KVStringApplication) EndBlock(req types.RequestEndBlock) types.ResponseEndBlock {
	return types.ResponseEndBlock{
		ValidatorUpdates: app.ValUpdates,
	}
}

func (app *KVStringApplication) Validator() (validators []types.ValidatorUpdate) {
	itr, _ := app.state.db.Iterator(nil, nil)
	for ; itr.Valid(); itr.Next() {
		if isValidatorTx(itr.Key()) {
			validator := new(types.ValidatorUpdate)
			err := types.ReadMessage(bytes.NewBuffer(itr.Value()), validator)
			if err != nil {
				panic(err)
			}
			validators = append(validators, *validator)
		}
	}
	return
}

func MakeValSetChangeTx(pubkey types.PubKey, power int64) []byte {
	pubStr := base64.StdEncoding.EncodeToString(pubkey.Data)
	return []byte(fmt.Sprintf("val:%s%d", pubStr, power))
}

func (app *KVStringApplication) execValidatorTx(tx []byte) types.ResponseDeliverTx {
	tx = tx[len(ValidatorSetChangePrefix):]

	pubKeyAndPower := strings.Split(string(tx), "!")
	if len(pubKeyAndPower) != 2 {
		return types.ResponseDeliverTx{
			Code: CodeTypeEncodingError,
			Log:  fmt.Sprintf("Expected 'pubkey!power'. Got %v", pubKeyAndPower),
		}
	}
	pubkeyS, powerS := pubKeyAndPower[0], pubKeyAndPower[1]

	// decode the pubkey
	pubkey, err := base64.StdEncoding.DecodeString(pubkeyS)
	if err != nil {
		return types.ResponseDeliverTx{
			Code: CodeTypeEncodingError,
			Log:  fmt.Sprintf("Pubkey (%s) is invalid base64", pubkeyS)}
	}

	// decode the power
	power, err := strconv.ParseInt(powerS, 10, 64)
	if err != nil {
		return types.ResponseDeliverTx{
			Code: CodeTypeEncodingError,
			Log:  fmt.Sprintf("Power (%s) is not an int", powerS)}
	}

	// update
	return app.updateValidator(types.Ed25519ValidatorUpdate(pubkey, power))
}

// add, update, or remove a validator
func (app *KVStringApplication) updateValidator(v types.ValidatorUpdate) types.ResponseDeliverTx {
	key := []byte("val:" + string(v.PubKey.Data))

	pubkey := ed25519.PubKeyEd25519{}
	copy(pubkey[:], v.PubKey.Data)

	if v.Power == 0 {
		// remove validator
		has, _ := app.state.db.Has(key)
		if !has {
			pubStr := base64.StdEncoding.EncodeToString(v.PubKey.Data)
			return types.ResponseDeliverTx{
				Code: CodeTypeUnauthorized,
				Log:  fmt.Sprintf("Cannot remove non-existent validator %s", pubStr)}
		}
		app.state.db.Delete(key)
		delete(app.valAddrToPubKeyMap, string(pubkey.Address()))
	} else {
		// add or update validator
		value := bytes.NewBuffer(make([]byte, 0))
		if err := types.WriteMessage(&v, value); err != nil {
			return types.ResponseDeliverTx{
				Code: CodeTypeEncodingError,
				Log:  fmt.Sprintf("Error encoding validator: %v", err)}
		}
		app.state.db.Set(key, value.Bytes())
		app.valAddrToPubKeyMap[string(pubkey.Address())] = v.PubKey
	}

	// we only update the changes array if we successfully updated the tree
	app.ValUpdates = append(app.ValUpdates, v)

	return types.ResponseDeliverTx{Code: CodeTypeOK}
}
