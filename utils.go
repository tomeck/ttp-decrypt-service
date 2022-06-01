package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
	"strings"
	"time"

	b64 "encoding/base64"

	"net/http"

	"log"

	"github.com/skythen/bertlv"
)

// Compose the API signature for a given API key+secret, body, time and clientRequestId
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

// Invoke the CommerceHub information-lookup endpoint for a card with the given PAN and expdate
func doBINLookup(PAN string, expMonth string, expYear string) (CardInfoResponse, error) {

	// The return value
	var cardInfoResponse CardInfoResponse

	// Setup the request to the info-lookup call
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

	// bodyString := string(body)

	// Setup headers to call CommerceHub endpoint
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

	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 200) {
		// handle error
		log.Println("Error invoking information-lookup endpoint:", resp.StatusCode)
		defer resp.Body.Close()
		respBody, _ := ioutil.ReadAll(resp.Body)
		log.Print(string(respBody))
		return cardInfoResponse, err
	} else {
		defer resp.Body.Close()
		respBody, _ := ioutil.ReadAll(resp.Body)
		log.Print(string(respBody))

		// Unmarshal the response data into a CardInfoResponse instance
		json.Unmarshal(respBody, &cardInfoResponse)
		return cardInfoResponse, nil
	}
}

// Extracts the PAN and expdate from the supplied EMV data string
// i.e. parses EMV tag 57
func getPANInfoFromEMVData(emvData string) (PAN, expMonth, expYear string, err error) {

	// Return values
	// var rPAN, rexpMonth, rexpYear string

	// Decode the EMV data into array of TLV structs
	tlvBytes, _ := hex.DecodeString(emvData)
	bertlvs, err := bertlv.Parse(tlvBytes)

	if err != nil {
		return "", "", "", err
	}

	// Attempt to find Tag 57 (which contains PAN, expdate)
	tag57 := bertlvs.FindFirstWithTag(bertlv.NewOneByteTag(byte(0x57)))
	log.Print(tag57)

	if tag57 == nil {
		return "", "", "", errors.New("Tag 57 was not found")
	}

	// Parse tag 57:
	//  from start of string to 'D' delimiter = PAN
	//  following two chars = YY
	//  following two chars = MM
	// tag57bytes, err := hex.DecodeString(tag57.Value)
	//TODO JTE need to check bounds and whether the format of Tag57 is valid
	sTag57 := fmt.Sprintf("%X", tag57.Value)
	splits := strings.SplitAfter(sTag57, "D")
	PAN = splits[0]
	expYear = "20" + splits[1][0:2] // <----- WARNING: I'm artificially converting YY to YYYY
	expMonth = splits[1][2:4]

	// return "370348394121029", "12", "2024", nil
	// return rPAN, rexpMonth, rexpYear, nil
	return
}
