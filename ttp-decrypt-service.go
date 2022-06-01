package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/gorilla/mux"

	"net/http"

	"log"
)

//
// Constants
//
const CHUB_INFO_LOOKUP_API_URL = "https://qa.api.fiservapps.com/ch/payments-vas/v1/accounts/information-lookup"

// TODO JTE need to look into which MID/TID to use on behalf of all calls to information-lookup
const SYSTEM_MERCHANT_ID = "100009000000441"
const SYSTEM_TERMINAL_ID = "10000002"

// TODO JTE - put these in Environment for security purposes
const key = "Kj4HzMB3B3AO352PpNyQTIafT30BB371"
const secret = "HmhExt7QBeDUCQiDBc72XGD3t5Nx7nNZy46mcPUqxUK"

// POST /decrypt handler
func decryptTTPBLob(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Declare a new EncryptedCardDataBlock struct to deserialize POST request body into
	var reqData DecryptRequest

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		http.Error(w, "{\"error\":"+err.Error()+"\"}", http.StatusBadRequest)
		return
	}

	//TODO JTE not sure why I have to manually check these, when I marked them required in the struct
	if reqData.PaymentCardData == "" {
		http.Error(w, "{'error':'You must provide paymentCardData'}", http.StatusBadRequest)
		return
	}

	// ************* ************* *************
	// PERFORM       DECRYPTION    HERE
	// ************* ************* *************
	var decryptErr error // TODO JTE this var represents whether decryption succeeded and we should return 200 from this func
	decryptErr = nil

	// TODO JTE - the plaintext from the TTP encrypted blob is being hardcoded for now
	emvData := "57134761739001010119D22122011143804400000F820220008407A0000000031010950500000000009A032109169C01005F2A0208405F3401019F02060000000032409F03060000000000009F100706010A03A000009F1A0208409F1E0863656139356330659F2608B0AAC2EA6FD424099F2701809F34033F00009F3501219F360204339F37049EEC77569F6E0420700080"

	// Initialize response entity
	decryptResponse := DecryptResponse{
		EMVData: emvData,
	}

	// Extract the PAN and expdate from the decrypted EMV data
	PAN, expMonth, expYear, err := getPANInfoFromEMVData(emvData)
	// TODO JTE if err!=nil, log a warning

	if err == nil {
		// Get BIN info for this card
		cardInfoResponse, err := doBINLookup(PAN, expMonth, expYear) //("370348394121029", "12", "2024")

		if err == nil {
			fmt.Println(cardInfoResponse)
			decryptResponse.ÇardDetails = cardInfoResponse.CardDetailsBlock
		}
	}

	if decryptErr == nil {
		json.NewEncoder(w).Encode(decryptResponse)
		// Implicitly returns status 200
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

// GET / handler (healthcheck)
func healthCheck(w http.ResponseWriter, r *http.Request) {
	// set header.
	w.Header().Set("Content-Type", "application/json")
}

func main() {

	// Init Router
	r := mux.NewRouter()

	// Set app routes
	r.HandleFunc("/decrypt", decryptTTPBLob).Methods("POST")

	// Health check endpoint
	r.HandleFunc("/", healthCheck).Methods("GET")

	// Start listening and handling token requests
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
		fmt.Printf("defaulting to port %s\n", port)
	}
	fmt.Println("Listening on port", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
