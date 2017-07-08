package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"github.com/btcsuite/btcd/btcec"
	"github.com/gorilla/mux"
	"net/http"
	"os"
)
type returnSignatureStructure struct {
    Signature   string `json:"signature,omitempty"`
}
var sign returnSignatureStructure

func determineListenAddress() (string, error) {
  port := os.Getenv("PORT")
  if port == "" {
    return "", fmt.Errorf("$PORT not set")
  }
  return ":" + port, nil
}

func returnSignature(w http.ResponseWriter, r *http.Request){
	vars := mux.Vars(r)
	var tosign string
	//to read the tosign key returned from the BlockCypher API
	tosign = vars["toSign"]
	//fmt.Scanf("%s", &tosign)
	//sample tosign = "646b5cc387cef8ced58d861c2ddae75568b4936ccb2971371a0f9d2321460381"
	data, err := hex.DecodeString(tosign)
	if err != nil {
		log.Fatal(err)
	}
	var privateKey string
	privateKey = vars["privateKey"]
	//to read the private key of the user
	//fmt.Scanf("%s", &privateKey)
	//sample privateKey = "b3bd48cbfc88ddcaa9b600c90a62a07fe6c27503ae5b4872c041e5aecf2e723d"
	priv, err := hex.DecodeString(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	sig, err := Sign(priv, data)
	if err != nil {
		log.Fatal(err)
	}
	var signature string
	//to create the ECDSA SECP256K1 signature for two step verification of the BlockCypher API
	signature = hex.EncodeToString(sig)
	fmt.Println(signature)
	sign.Signature = signature
	json.NewEncoder(w).Encode(sign)
}

func Sign(private, data []byte) ([]byte, error) {
	privkey, _ := btcec.PrivKeyFromBytes(btcec.S256(), private)
	sig, err := privkey.Sign(data)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func home(w http.ResponseWriter, r *http.Request){
	fmt.Println("successfully connected")
}

func main() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/signature/{privateKey}/{toSign}", returnSignature).Name("/signature/{privateKey}/{toSign}").Methods("GET")
	myRouter.HandleFunc("/home", home)
	addr, err := determineListenAddress()
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", myRouter)
	log.Printf("Listening on %s...\n", addr)
  if err := http.ListenAndServe(addr, nil); err != nil {
    panic(err)
  }
	//log.Fatal(http.ListenAndServe(":8080", myRouter))
}
