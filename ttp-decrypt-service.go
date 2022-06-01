package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	b64 "encoding/base64"

	"net/http"

	"log"
)

// Constants
const CHUB_INFO_LOOKUP_API_URL = "https://qa.api.fiservapps.com/ch/payments-vas/v1/accounts/information-lookup"
const SYSTEM_MERCHANT_ID = "100009000000441"
const SYSTEM_TERMINAL_ID = "10000002"

// JTE TODO - put these in Environment for security purposes
const key = "lq6sRHxltHk4PkB4myfSGalRzK9kvcir"
const secret = "vZ9UUZ5gtzUPlbia8BgC2G6qzDJGmli38G1osZjJPDz"

// The following structure is the request payload for this service's /decrypt endpoint
type DecryptRequest struct {
	PaymentCardData string `json:"paymentCardData" validate:"required"`
}

// The following structures are related to the response from Apple's TTP /translate endpoint
type DataValidationBlock struct {
	Format string `json:"format" validate:"required"`
	Value  string `json:"value" validate:"required"`
}

type EncryptedCardDataBlock struct {
	Ciphertext                    string              `json:"cipherText" validate:"required"`
	CipherTextEncryptionAlgorithm string              `json:"cipherTextEncryptionAlgorithm" validate:"required"`
	DataEncryptionKeyBlock        string              `json:"dataEncryptionKeyBlock" validate:"required"`
	DataEncryptionKeyBlockFormat  string              `json:"dataEncryptionKeyBlockFormat" validate:"required"`
	KekId                         string              `json:"kekId" validate:"required"`
	IV                            string              `json:"iv" validate:"required"`
	DataValidationBlock           DataValidationBlock `json:"dataValidation" validate:"required"`
}

type TranslateResponse struct {
	EncryptedCardDataBlock  EncryptedCardDataBlock `json:"encryptedCardData" validate:"required"`
	UtcTransactionDateTime  string                 `json:"utcTransactionDateTime" validate:"required"`
	CardReaderTransactionId string                 `json:"cardReaderTransactionId" validate:"required"`
	CardReaderId            string                 `json:"cardReaderId" validate:"required"`
}

// The following structures comprise the request payload for the internal call to the CommerceHub BIN lookup service
type CardBlock struct {
	CardData        string `json:"cardData" validate:"required"`
	ExpirationMonth string `json:"expirationMonth" validate:"required"`
	ExpirationYear  string `json:"expirationYear" validate:"required"`
}

type SourceBlock struct {
	SourceType string    `json:"sourceType" validate:"required"`
	CardBlock  CardBlock `json:"card" validate:"required"`
}

type MerchantDetailsBlock struct {
	MerchantId string `json:"merchantId" validate:"required"`
	TerminalId string `json:"terminalId" validate:"required"`
}

type CardInfoRequest struct {
	SourceBlock          SourceBlock          `json:"source" validate:"required"`
	MerchantDetailsBlock MerchantDetailsBlock `json:"merchantDetails" validate:"required"`
}

// The following structures comprise the response payload from the internal call to the CommerceHub BIN lookup service
type CardDetailsBlock struct {
	RecordType             string `json:"recordType" validate:"required"`
	LowBin                 string `json:"lowBin" validate:"required"`
	HighBin                string `json:"highBin" validate:"required"`
	BinLength              string `json:"binLength" validate:"required"`
	BinDetailPan           string `json:"binDetailPan" validate:"required"`
	DetailedCardProduct    string `json:"detailedCardProduct" validate:"required"`
	DetailedCardIndicator  string `json:"detailedCardIndicator" validate:"required"`
	PinSignatureCapability string `json:"pinSignatureCapability" validate:"required"`
	IssuerUpdateYear       string `json:"issuerUpdateYear" validate:"required"`
	IssuerUpdateMonth      string `json:"issuerUpdateMonth" validate:"required"`
	IssuerUpdateDay        string `json:"issuerUpdateDay" validate:"required"`
	RegulatorIndicator     string `json:"regulatorIndicator" validate:"required"`
	AccountFundSource      string `json:"accountFundSource" validate:"required"`
	PanLengthMin           string `json:"panLengthMin" validate:"required"`
	PanLengthMax           string `json:"panLengthMax" validate:"required"`
}

type CardInfoResponse struct {
	CardDetailsBlock CardDetailsBlock `json:"cardDetails" validate:"required"`
}

// POST /decrypt handler
func decryptTTPBLob(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Declare a new EncryptedCardDataBlock struct to deserialize POST body into
	var reqData DecryptRequest

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		http.Error(w, "{\"error\":"+err.Error()+"\"}", http.StatusBadRequest)
		return
	}

	//TODO JTE not sure why I have to manually check these, when I marked them required in the struct
	// if reqData.Mbn == "" || reqData.Mcc == "" || reqData.Mid == "" || reqData.Tpid == "" {
	// 	http.Error(w, "{'error':'You must provide mbn, mcc, mid, and tpid'}", http.StatusBadRequest)
	// 	return
	// }

	// tokenString, err := generateJWT(reqData)

	// TODO JTE - I'm returning the same value for every call; this is the sample
	// plaintext provided by Apple
	plainText := "57134761739001010119D22122011143804400000F820220008407A0000000031010950500000000009A032109169C01005F2A0208405F3401019F02060000000032409F03060000000000009F100706010A03A000009F1A0208409F1E0863656139356330659F2608B0AAC2EA6FD424099F2701809F34033F00009F3501219F360204339F37049EEC77569F6E0420700080"

	// Get BIN info for this card
	cardInfoResponse, err := doBINLookup("370348394121029", "12", "2024")
	fmt.Println(cardInfoResponse)

	if err == nil {
		w.Write([]byte("{\"tlvs\":\"" + plainText + "\"}"))
		// Implicitly returns status 200
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

func getSignature(key string, secret string, data string, time int64, clientRequestId int) string {

	rawSignature := key + fmt.Sprint(clientRequestId) + fmt.Sprint(time) + data

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(rawSignature))

	// Get result and encode as Base64 string
	sha := b64.StdEncoding.EncodeToString([]byte(h.Sum(nil)))

	return sha
}

func doBINLookup(PAN string, expMonth string, expYear string) (CardInfoResponse, error) {

	// The return value
	var cardInfoResponse CardInfoResponse

	// Setup the request to the info-lookup
	cardBlock := CardBlock{
		CardData:        PAN,
		ExpirationMonth: expMonth,
		ExpirationYear:  expYear,
	}

	merchantDetailsBlock := MerchantDetailsBlock{
		MerchantId: SYSTEM_MERCHANT_ID,
		TerminalId: SYSTEM_TERMINAL_ID,
	}

	sourceBlock := SourceBlock{
		SourceType: "PaymentCard",
		CardBlock:  cardBlock,
	}

	cardInfoRequest := CardInfoRequest{
		SourceBlock:          sourceBlock,
		MerchantDetailsBlock: merchantDetailsBlock,
	}

	// Convert JSON request object to bytes
	body, _ := json.Marshal(cardInfoRequest)

	// Setup headers to call CommerceHub
	time := time.Now().UnixNano() / int64(time.Millisecond)

	// Generate a nice random number (seeded w/current time) for idempotency check
	randSource := rand.NewSource(time)
	clientRequestId := rand.New(randSource).Intn(10000000) + 1

	signature := getSignature(key, secret, string(body), time, clientRequestId)

	// Invoke the CommerceHub POST information-lookup endpoint
	req, err := http.NewRequest("POST", CHUB_INFO_LOOKUP_API_URL, bytes.NewBuffer(body))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept-language", "en")
	req.Header.Add("Auth-Token-Type", "HMAC")
	req.Header.Add("Timestamp", strconv.Itoa(int(time)))
	req.Header.Add("Api-Key", key)
	req.Header.Add("Client-Request-Id", strconv.Itoa(int(clientRequestId)))
	req.Header.Add("Authorization", signature)

	client := &http.Client{}
	resp, err := client.Do(req)

	var respBody []byte
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 200) {
		// handle error
		log.Println("Error invoking information-lookup endpoint:", resp.StatusCode)
		defer resp.Body.Close()
		respBody, _ = ioutil.ReadAll(resp.Body)
		log.Print(string(respBody))
	} else {
		defer resp.Body.Close()
		respBody, _ = ioutil.ReadAll(resp.Body)
		log.Print(string(respBody))

		// jsonResp := gjson.Parse(string(body))
	}

	// Unmarshal the response data into a CardInfoResponse instance
	json.Unmarshal(respBody, &cardInfoResponse)

	return cardInfoResponse, nil
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
