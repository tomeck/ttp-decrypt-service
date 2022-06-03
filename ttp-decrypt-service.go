package main

import (
	"encoding/hex"
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
	if reqData.Mid == "" || reqData.PaymentCardData == "" || reqData.RecryptKey == "" {
		http.Error(w, "{'error':'You must provide mid, paymentCardData and recryptKey'}", http.StatusBadRequest)
		return
	}

	// ************* ************* *************
	// INVOKE        TRANSLATE ENDPOINT    HERE
	// ************* ************* *************
	// These values are returned from the Translate endpoint,
	// except for the KBPKString, which is configured on Fiserv end
	const KBPKString = "000102030405060708090A0B0C0D0E0F"
	const ivString = "IcwCU76mqH140fiNG6s/Dw=="
	const cipherText = "Cy4VafCZ4a/qq594JmflyR1spzRgGAEnUPdoK+y3hkhqGl9F+m7ivByPN+DiL6KN/E9CaIRe6Ku01kdIixrteIU8cySMwShQU1EpCxR0ZMQTL/JTXFqRUqdFykSi4VLZeOGeNd9cn7I9jNbTFOshZRloLjjGqPnWSxj3B15kpn3u4KaZ+Kics6NGw3Dx48RW4toTofIwdnMdvFi+pl83cw=="
	const dataEncryptionKeyBlockString = "D0112D0AD00E00001821d8e88ee4eef8dae88762759518e0ce897bb05e0d1dbb1b3ef7fb03b4d784513599f96af89c1624c1aa6d257d5903"

	// ************* ************* *************
	// PERFORM       DECRYPTION    HERE
	// ************* ************* *************
	var decryptErr error = nil // TODO JTE this var represents whether decryption succeeded and we should return 200 from this func

	// Get the one-time decryption key
	KBPK, _ := hex.DecodeString(KBPKString)
	KBEK, err := GetDecryptionKeyFromKeyblock(KBPK, dataEncryptionKeyBlockString)
	if err != nil {
		panic(err) //TODO JTE
	}

	emvData, err := DecryptTTPCipherText(KBEK, ivString, cipherText)
	if err != nil {
		panic(err) //TODO JTE
	}

	// TODO JTE - the plaintext from the TTP encrypted blob is being hardcoded for now
	// emvData := "57134761739001010119D22122011143804400000F820220008407A0000000031010950500000000009A032109169C01005F2A0208405F3401019F02060000000032409F03060000000000009F100706010A03A000009F1A0208409F1E0863656139356330659F2608B0AAC2EA6FD424099F2701809F34033F00009F3501219F360204339F37049EEC77569F6E0420700080"

	// Initialize response entity
	decryptResponse := DecryptResponse{}

	// Extract the PAN and expdate from the decrypted EMV data
	PAN, expMonth, expYear, err := getPANInfoFromEMVData(string(emvData))

	if err == nil {
		// Get BIN info for this card
		cardInfoResponse, err := doBINLookup(PAN, expMonth, expYear) //("370348394121029", "12", "2024")

		if err == nil {
			fmt.Println(cardInfoResponse)
			decryptResponse.ÇardDetails = cardInfoResponse.CardDetailsBlock
		} else {
			//TODO JTE handle this error better?
			fmt.Println("Error performing BIN lookup", err)
		}
	} else {
		//TODO JTE handle this error better?
		fmt.Println("Error getting PAN info from EMV data", err)
	}

	// ************* ************* *************
	// RE_ENCRYPT    PAN           HERE
	// ************* ************* *************
	reencryptedPan := PAN
	decryptResponse.EncryptedPAN = reencryptedPan

	// ************* ************* *************
	// MASK          PAN           HERE
	// ************* ************* *************
	decryptResponse.EMVData = string(emvData)

	// HTTP response
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
