package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func GeneratePrivateKeysInFile(numSigners int, name string) {
	// create file
	f, err := os.Create(name)
	if err != nil {
		log.Fatal(err)
	}
	// remember to close the file
	defer f.Close()
	for i := 0; i < numSigners; i++ {
		privKey, err := btcec.NewPrivateKey()
		if err != nil {
			panic(fmt.Sprintf("unable to gen priv key: %v", err))
		}
		wif, err := btcutil.NewWIF(privKey, &net, true)
		if err != nil {
			panic(fmt.Sprintf("btcutil.NewWIF error: %v", err))
		}

		_, err = f.WriteString(wif.String() + "\n")
		if err != nil {
			panic(fmt.Sprintf("f.WriteString error: %v", err))
		}
	}
}

func BuildRawTx() *wire.MsgTx {

	// tb1qg7akyhjf6nmenw8w6g9kxtz0zl0z2zv99n9dyx
	// https://blockstream.info/testnet/tx/1c72f20c44078dbbd2582db5014fd7ffde45de4798596e98203d25370175293a
	tx := wire.NewMsgTx(2)
	utxoHash, _ := chainhash.NewHashFromStr("1c72f20c44078dbbd2582db5014fd7ffde45de4798596e98203d25370175293a")
	point := wire.OutPoint{Hash: *utxoHash, Index: 0}
	tx.AddTxIn(wire.NewTxIn(&point, nil, nil))

	address, err := btcutil.DecodeAddress("tb1qg7akyhjf6nmenw8w6g9kxtz0zl0z2zv99n9dyx", &net)
	if err != nil {
		panic(fmt.Sprintf("btcutil.DecodeAddress error: %v", err))
	}
	pkScript, err := txscript.PayToAddrScript(address)
	if err != nil {
		panic(fmt.Sprintf("txscript.PayToAddrScript error: %v", err))
	}
	tx.AddTxOut(wire.NewTxOut(19000, pkScript))

	return tx
}

func BuildSingleSignRawTx() *wire.MsgTx {

	// tb1qg7akyhjf6nmenw8w6g9kxtz0zl0z2zv99n9dyx
	// https://blockstream.info/testnet/tx/47b5058b8b28a0588dd64692290bd2ddff3a3ad0dd664cfc96a7c56fa0584b21
	tx := wire.NewMsgTx(2)
	utxoHash, _ := chainhash.NewHashFromStr("47b5058b8b28a0588dd64692290bd2ddff3a3ad0dd664cfc96a7c56fa0584b21")
	point := wire.OutPoint{Hash: *utxoHash, Index: 0}
	tx.AddTxIn(wire.NewTxIn(&point, nil, nil))

	address, err := btcutil.DecodeAddress("tb1qg7akyhjf6nmenw8w6g9kxtz0zl0z2zv99n9dyx", &net)
	if err != nil {
		panic(fmt.Sprintf("btcutil.DecodeAddress error: %v", err))
	}
	pkScript, err := txscript.PayToAddrScript(address)
	if err != nil {
		panic(fmt.Sprintf("txscript.PayToAddrScript error: %v", err))
	}
	tx.AddTxOut(wire.NewTxOut(19000, pkScript))

	return tx
}

func SignRawTransaction(tx *wire.MsgTx, tapLeaf txscript.TapLeaf, privKey *btcec.PrivateKey) []byte {
	scriptHash, err := hex.DecodeString("5120f9a19eb5e4cd25387e43187039a947c0a73cb9ea8f02e4d43768198c84ae3f4c")
	if err != nil {
		panic(fmt.Sprintf("hex.DecodeString error: %v", err))
	}
	value := int64(20000)
	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		scriptHash,
		value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, inputFetcher)
	sig, err := txscript.RawTxInTapscriptSignature(
		tx, sigHashes, 0, value,
		scriptHash, tapLeaf, txscript.SigHashDefault,
		privKey)
	return sig
}
