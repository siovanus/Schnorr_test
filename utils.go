package main

import (
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
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
