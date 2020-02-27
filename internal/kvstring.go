package kvstring

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

type ValidatorUpdateDate struct {
	PubKey string `json:"pubkey"`
	Power  int64  `json:"power"`
}

type RequestData struct {
	Type      string              `json:"type"`
	User      string              `json:"user"`
	Location  []string            `json:"location"`
	Date      string              `json:"date"`
	FileHash  string              `json:"fileHash"`
	Validator ValidatorUpdateDate `json:"validator"`
	Hash      string
}

type UserTransIndex struct {
	TransactionRecords []string `json:"transactions"`
	NextKey            string   `json:"nextKey"`
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

func (app *KVStringApplication) execTransaction(req RequestData) types.ResponseDeliverTx {
	fmt.Println("hello,execTransaction")
	value, _ := json.Marshal(req)
	if req.User == "" || len(req.Location) != 2 || req.FileHash == "" || req.Date == "" {
		fmt.Printf("execTransaction: bad request %s \n", string(value))
		events := []types.Event{
			{
				Type: "app",
				Attributes: []kv.Pair{
					{Key: []byte("creator"), Value: []byte("Cosmoshi Netowoko")},
					{Key: []byte("key"), Value: value},
				},
			},
		}

		return types.ResponseDeliverTx{Code: CodeTypeUnknownError, Events: events}
	}

	// get current user index
	var currentIndex UserTransIndex
	userIndex, err := app.state.db.Get([]byte(req.User))

	if err != nil || userIndex == nil {
		// update current index
		currentIndex.TransactionRecords = append(currentIndex.TransactionRecords, string(req.Hash))

		valueBytes, err := json.Marshal(currentIndex)
		if err != nil {
			fmt.Printf("execTransaction 2 %v \n", err)
		}

		err = app.state.db.Set([]byte(req.User), valueBytes)
		if err != nil {
			fmt.Printf("execTransaction 3 %v \n", err)
		}

	} else {
		err := json.Unmarshal(userIndex, &currentIndex)
		if err != nil {
			fmt.Printf("execTransaction %v \n %s \n%v\n", err, string(userIndex), currentIndex)
			events := []types.Event{
				{
					Type: "app",
					Attributes: []kv.Pair{
						{Key: []byte("creator"), Value: []byte("Cosmoshi Netowoko")},
						{Key: []byte("key"), Value: userIndex},
					},
				},
			}

			return types.ResponseDeliverTx{Code: CodeTypeUnknownError, Events: events}
		} else {
			if len(currentIndex.TransactionRecords) > 127 {
				// create a new index
				newKey := req.User + Str(6)
				currentIndex.NextKey = newKey
				var newIndexes UserTransIndex
				newIndexes.TransactionRecords = append(newIndexes.TransactionRecords, string(req.Hash))
				// save new index
				//save
				valueBytes, err := json.Marshal(newIndexes)
				if err != nil {
					fmt.Printf("execTransaction 2-2 %v \n", err)
				}

				err = app.state.db.Set([]byte(newKey), valueBytes)
				if err != nil {
					fmt.Printf("execTransaction 3-2 %v \n", err)
				}

			} else {

			}

			//save current indexes
			valueBytes, err := json.Marshal(currentIndex)
			if err != nil {
				fmt.Printf("execTransaction 2-2 %v \n", err)
			}

			err = app.state.db.Set([]byte(req.User), valueBytes)
			if err != nil {
				fmt.Printf("execTransaction 3-2 %v \n", err)
			}
		}
	}

	// save transaction
	app.state.db.Set([]byte(req.Hash), value)

	events := []types.Event{
		{
			Type: "app",
			Attributes: []kv.Pair{
				{Key: []byte("creator"), Value: []byte("CoT Network")},
				{Key: []byte("key"), Value: []byte(req.Hash)},
			},
		},
	}
	return types.ResponseDeliverTx{Code: CodeTypeOK, Events: events}
}

func (app *KVStringApplication) DeliverTx(req types.RequestDeliverTx) types.ResponseDeliverTx {
	fmt.Println("hello,DeliverTx")
	var requestData RequestData
	decode, err := base64.StdEncoding.DecodeString(string(req.Tx))
	req.Tx = decode
	err = json.Unmarshal(req.Tx, &requestData)
	if err != nil {
		fmt.Printf("%s", err)
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

	if requestData.Type == TypeValidatorUpdating {
		return app.execValidatorTx(requestData.Validator)
	} else if requestData.Type == TypeTransaction {
		hash := md5.New()
		hash.Write(req.Tx)
		requestData.Hash = hex.EncodeToString(hash.Sum(nil))
		return app.execTransaction(requestData)
	} else {
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
}

func (app *KVStringApplication) CheckTx(req types.RequestCheckTx) types.ResponseCheckTx {
	fmt.Println("hello,CheckTx")
	return types.ResponseCheckTx{Code: CodeTypeOK, GasWanted: 1}
}

func (app *KVStringApplication) Commit() types.ResponseCommit {
	fmt.Println("hello,Commit")
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
	case "val":
		key := []byte("val:" + string(reqQuery.Data))
		value, _ := app.state.db.Get(key)
		resQuery.Key = reqQuery.Data
		resQuery.Value = value
		return
	case "user":
		value, _ := app.state.db.Get(reqQuery.Data)
		resQuery.Key = reqQuery.Data
		resQuery.Value = value
		return
	default:

		if reqQuery.Prove {
			value, _ := app.state.db.Get(reqQuery.Data)
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
		value, _ := app.state.db.Get(reqQuery.Data)
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
			fmt.Printf("Error updating validators %v\n", r)
		}
	}
	return types.ResponseInitChain{}
}

func (app *KVStringApplication) BeginBlock(req types.RequestBeginBlock) types.ResponseBeginBlock {
	fmt.Println("hello,BeginBlock")
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
	fmt.Println("hello,EndBlock")
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

func (app *KVStringApplication) execValidatorTx(tx ValidatorUpdateDate) types.ResponseDeliverTx {

	// decode the pubkey
	pubkey, err := base64.StdEncoding.DecodeString(tx.PubKey)
	if err != nil {
		return types.ResponseDeliverTx{
			Code: CodeTypeEncodingError,
			Log:  fmt.Sprintf("Pubkey (%s) is invalid base64", tx.PubKey)}
	}

	// update
	return app.updateValidator(types.Ed25519ValidatorUpdate(pubkey, tx.Power))
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
