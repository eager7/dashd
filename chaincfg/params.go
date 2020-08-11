// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"errors"
	"github.com/eager7/dashd/chaincfg/chainhash"
	"math/big"

	"github.com/eager7/dashd/wire"
)
const (
	DeploymentSegwit = 1
	BIP0065Height = 1
	DeploymentTestDummy = "DeploymentTestDummy"
	DeploymentCSV = "DeploymentCSV"
)
// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a Bitcoin block can
	// have for the main network.  It is the value 2^224 - 1.
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// regressionPowLimit is the highest proof of work value a Bitcoin block
	// can have for the regression test network.  It is the value 2^255 - 1.
	regressionPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// testNet3PowLimit is the highest proof of work value a Bitcoin block
	// can have for the test network (version 3).  It is the value
	// 2^224 - 1.
	testNet3PowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// simNetPowLimit is the highest proof of work value a Bitcoin block
	// can have for the simulation test network.  It is the value 2^255 - 1.
	simNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height int32
	Hash   *chainhash.Hash
}

// Params defines a Bitcoin network by its parameters.  These parameters may be
// used by Bitcoin applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	Name        string
	Net         wire.BitcoinNet
	DefaultPort string
	DNSSeeds    []string

	// Chain parameters
	GenesisBlock           *wire.MsgBlock
	GenesisHash            *chainhash.Hash
	PowLimit               *big.Int
	PowLimitBits           uint32
	SubsidyHalvingInterval int32
	ResetMinDifficulty     bool
	GenerateSupported      bool

	BIP0034Height int32
	BIP0065Height int32
	BIP0066Height int32
	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// Enforce current block version once network has
	// upgraded.  This is part of BIP0034.
	BlockEnforceNumRequired uint64

	// Reject previous block versions once network has
	// upgraded.  This is part of BIP0034.
	BlockRejectNumRequired uint64

	// The number of nodes to check.  This is part of BIP0034.
	BlockUpgradeNumToCheck uint64

	// Mempool parameters
	RelayNonStdTxs bool

	// Address encoding magics
	PubKeyHashAddrID byte // First byte of a P2PKH address
	ScriptHashAddrID byte // First byte of a P2SH address
	PrivateKeyID     byte // First byte of a WIF private key

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32
}

// MainNetParams defines the network parameters for the main Bitcoin network.
var MainNetParams = Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	DefaultPort: "8333",
	DNSSeeds: []string{
		"seed.bitcoin.sipa.be",
		"dnsseed.bluematt.me",
		"dnsseed.bitcoin.dashjr.org",
		"seed.bitcoinstats.com",
		"seed.bitnodes.io",
		"bitseed.xf2.org",
		"seed.bitcoin.jonasschnelli.ch",
	},

	// Chain parameters
	GenesisBlock:           &genesisBlock,
	GenesisHash:            &genesisHash,
	PowLimit:               mainPowLimit,
	PowLimitBits:           0x1d00ffff,
	SubsidyHalvingInterval: 210240,
	ResetMinDifficulty:     false,
	GenerateSupported:      false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{1500, newShaHashFromStr("000000aaf0300f59f49bc3e970bad15c11f961fe2347accffff19d96ec9778e3")},
		{4991, newShaHashFromStr("000000003b01809551952460744d5dbb8fcbd6cbae3c220267bf7fa43f837367")},
		{9918, newShaHashFromStr("00000000213e229f332c0ffbe34defdaa9e74de87f2d8d1f01af8d121c3c170b")},
		{16912, newShaHashFromStr("00000000075c0d10371d55a60634da70f197548dbbfa4123e12abfcbc5738af9")},
		{23912, newShaHashFromStr("0000000000335eac6703f3b1732ec8b2f89c3ba3a7889e5767b090556bb9a276")},
		{35457, newShaHashFromStr("0000000000b0ae211be59b048df14820475ad0dd53b9ff83b010f71a77342d9f")},
		{45479, newShaHashFromStr("000000000063d411655d590590e16960f15ceea4257122ac430c6fbe39fbf02d")},
		{55895, newShaHashFromStr("0000000000ae4c53a43639a4ca027282f69da9c67ba951768a20415b6439a2d7")},
		{68899, newShaHashFromStr("0000000000194ab4d3d9eeb1f2f792f21bb39ff767cb547fe977640f969d77b7")},
		{74619, newShaHashFromStr("000000000011d28f38f05d01650a502cc3f4d0e793fbc26e2a2ca71f07dc3842")},
		{75095, newShaHashFromStr("0000000000193d12f6ad352a9996ee58ef8bdc4946818a5fec5ce99c11b87f0d")},
		{88805, newShaHashFromStr("00000000001392f1652e9bf45cd8bc79dc60fe935277cd11538565b4a94fa85f")},
		{107996, newShaHashFromStr("00000000000a23840ac16115407488267aa3da2b9bc843e301185b7d17e4dc40")},
		{137993, newShaHashFromStr("00000000000cf69ce152b1bffdeddc59188d7a80879210d6e5c9503011929c3c")},
		{167996, newShaHashFromStr("000000000009486020a80f7f2cc065342b0c2fb59af5e090cd813dba68ab0fed")},
		{207992, newShaHashFromStr("00000000000d85c22be098f74576ef00b7aa00c05777e966aff68a270f1e01a5")},
		{312645, newShaHashFromStr("0000000000059dcb71ad35a9e40526c44e7aae6c99169a9e7017b7d84b1c2daf")},
		{407452, newShaHashFromStr("000000000003c6a87e73623b9d70af7cd908ae22fee466063e4ffc20be1d2dbc")},
		{523412, newShaHashFromStr("000000000000e54f036576a10597e0e42cc22a5159ce572f999c33975e121d4d")},
		{523930, newShaHashFromStr("0000000000000bccdb11c2b1cfb0ecab452abf267d89b7f46eaf2d54ce6e652c")},
		{750000, newShaHashFromStr("00000000000000b4181bbbdddbae464ce11fede5d0292fb63fdede1e7c8ab21c")},
		{888900, newShaHashFromStr("0000000000000026c29d576073ab51ebd1d3c938de02e9a44c7ee9e16f82db28")},
		{967800, newShaHashFromStr("0000000000000024e26c7df7e46d673724d223cf4ca2b2adc21297cc095600f4")},
		{1067570, newShaHashFromStr("000000000000001e09926bcf5fa4513d23e870a34f74e38200db99eb3f5b7a70")},
		{1167570, newShaHashFromStr("000000000000000fb7b1e9b81700283dff0f7d87cf458e5edfdae00c669de661")},
	},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 75% (750 / 1000)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 95% (950 / 1000)
	BlockEnforceNumRequired: 750,
	BlockRejectNumRequired:  950,
	BlockUpgradeNumToCheck:  1000,

	// Mempool parameters
	RelayNonStdTxs: false,

	// Address encoding magics
	PubKeyHashAddrID: 0x4c, // starts with X
	ScriptHashAddrID: 0x10, // starts with 7
	PrivateKeyID:     0xcc, // Dash private keys start with '7' or 'X'

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xAD, 0xE4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xB2, 0x1E}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 5,
}

// RegressionNetParams defines the network parameters for the regression test
// Bitcoin network.  Not to be confused with the test Bitcoin network (version
// 3), this network is sometimes simply called "testnet".
var RegressionNetParams = Params{
	Name:        "regtest",
	Net:         wire.TestNet,
	DefaultPort: "18444",
	DNSSeeds:    []string{},

	// Chain parameters
	GenesisBlock:           &regTestGenesisBlock,
	GenesisHash:            &regTestGenesisHash,
	PowLimit:               regressionPowLimit,
	PowLimitBits:           0x207fffff,
	SubsidyHalvingInterval: 150,
	ResetMinDifficulty:     true,
	GenerateSupported:      true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Enforce current block version once majority of the network has
	// upgraded.
	// 75% (750 / 1000)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 95% (950 / 1000)
	BlockEnforceNumRequired: 750,
	BlockRejectNumRequired:  950,
	BlockUpgradeNumToCheck:  1000,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x6f, // starts with m or n
	ScriptHashAddrID: 0xc4, // starts with 2
	PrivateKeyID:     0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}

// TestNet3Params defines the network parameters for the test Bitcoin network
// (version 3).  Not to be confused with the regression test network, this
// network is sometimes simply called "testnet".
var TestNet3Params = Params{
	Name:        "testnet3",
	Net:         wire.TestNet3,
	DefaultPort: "18333",
	DNSSeeds: []string{
		"testnet-seed.bitcoin.schildbach.de",
		"testnet-seed.bitcoin.petertodd.org",
		"testnet-seed.bluematt.me",
	},

	// Chain parameters
	GenesisBlock:           &testNet3GenesisBlock,
	GenesisHash:            &testNet3GenesisHash,
	PowLimit:               testNet3PowLimit,
	PowLimitBits:           0x1d00ffff,
	SubsidyHalvingInterval: 210240,
	ResetMinDifficulty:     true,
	GenerateSupported:      false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{261, newShaHashFromStr("00000c26026d0815a7e2ce4fa270775f61403c040647ff2c3091f99e894a4618")},
		{1999, newShaHashFromStr("00000052e538d27fa53693efe6fb6892a0c1d26c0235f599171c48a3cce553b1")},
		{2999, newShaHashFromStr("0000024bc3f4f4cb30d29827c13d921ad77d2c6072e586c7f60d83c2722cdcc5")},
		{96090, newShaHashFromStr("00000000033df4b94d17ab43e999caaf6c4735095cc77703685da81254d09bba")},
		{200000, newShaHashFromStr("000000001015eb5ef86a8fe2b3074d947bc972c5befe32b28dd5ce915dc0d029")},
	},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x8c, // Testnet Dash addresses start with 'y'
	ScriptHashAddrID: 0x13, // Testnet Dash script addresses start with '8' or '9'
	PrivateKeyID:     0xef, // Testnet private keys start with '9' or 'c' (Bitcoin defaults)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}

// SimNetParams defines the network parameters for the simulation test Bitcoin
// network.  This network is similar to the normal test network except it is
// intended for private use within a group of individuals doing simulation
// testing.  The functionality is intended to differ in that the only nodes
// which are specifically specified are used to create the network rather than
// following normal discovery rules.  This is important as otherwise it would
// just turn into another public testnet.
var SimNetParams = Params{
	Name:        "simnet",
	Net:         wire.SimNet,
	DefaultPort: "18555",
	DNSSeeds:    []string{}, // NOTE: There must NOT be any seeds.

	// Chain parameters
	GenesisBlock:           &simNetGenesisBlock,
	GenesisHash:            &simNetGenesisHash,
	PowLimit:               simNetPowLimit,
	PowLimitBits:           0x207fffff,
	SubsidyHalvingInterval: 210000,
	ResetMinDifficulty:     true,
	GenerateSupported:      true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x3f, // starts with S
	ScriptHashAddrID: 0x7b, // starts with s
	PrivateKeyID:     0x64, // starts with 4 (uncompressed) or F (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x20, 0xb9, 0x00}, // starts with sprv
	HDPublicKeyID:  [4]byte{0x04, 0x20, 0xbd, 0x3a}, // starts with spub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 115, // ASCII for s
}

var (
	// ErrDuplicateNet describes an error where the parameters for a Bitcoin
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate Bitcoin network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")
)

var (
	registeredNets    = make(map[wire.BitcoinNet]struct{})
	pubKeyHashAddrIDs = make(map[byte]struct{})
	scriptHashAddrIDs = make(map[byte]struct{})
	hdPrivToPubKeyIDs = make(map[[4]byte][]byte)
)

// Register registers the network parameters for a Bitcoin network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	pubKeyHashAddrIDs[params.PubKeyHashAddrID] = struct{}{}
	scriptHashAddrIDs[params.ScriptHashAddrID] = struct{}{}
	hdPrivToPubKeyIDs[params.HDPrivateKeyID] = params.HDPublicKeyID[:]
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsScriptHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsPubKeyHashAddrID(id byte) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsPubKeyHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsScriptHashAddrID(id byte) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newShaHashFromStr converts the passed big-endian hex string into a
// wire.ShaHash.  It only differs from the one available in wire in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newShaHashFromStr(hexStr string) *chainhash.Hash {
	sha, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return sha
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&MainNetParams)
	mustRegister(&TestNet3Params)
	mustRegister(&RegressionNetParams)
	mustRegister(&SimNetParams)
}