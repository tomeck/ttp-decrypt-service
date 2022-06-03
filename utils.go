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

	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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
	req, _ := http.NewRequest("POST", CHUB_INFO_LOOKUP_API_URL, bytes.NewBuffer(body))
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

		if err == nil {
			err = fmt.Errorf("error performing BIN lookup, status=%d", resp.StatusCode)
		}
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
func getPANInfoFromEMVData(emvData []byte) (PAN, expMonth, expYear string, err error) {

	// Return values
	// var rPAN, rexpMonth, rexpYear string

	// Decode the EMV data into array of TLV structs
	tlvBytes, _ := hex.DecodeString(string(emvData))
	bertlvs, err := bertlv.Parse(tlvBytes)

	if err != nil {
		return "", "", "", err
	}

	// Attempt to find Tag 57 (which contains PAN, expdate)
	tag57 := bertlvs.FindFirstWithTag(bertlv.NewOneByteTag(byte(0x57)))
	// log.Print(tag57)

	if tag57 == nil {
		return "", "", "", errors.New("Tag 57 was not found")
	}

	// Parse tag 57:
	//  from start of string to 'D' delimiter = PAN
	//  following two chars = YY
	//  following two chars = MM
	//TODO JTE need to check bounds and whether the format of Tag57 is valid
	sTag57 := fmt.Sprintf("%X", tag57.Value)
	splits := strings.Split(sTag57, "D")

	// Set return values
	PAN = splits[0]
	expYear = "20" + splits[1][0:2] // <----- WARNING: I'm artificially converting YY to YYYY
	expMonth = splits[1][2:4]

	return
}

// Mask the PAN in Tag57 in the supplied TLV byte array
// Returns the entire TLV array encoded as hex string
func MaskPanTag57(emvData []byte) (string, error) {

	// Decode the EMV data into array of TLV structs
	tlvBytes, _ := hex.DecodeString(string(emvData))
	bertlvs, err := bertlv.Parse(tlvBytes)

	if err != nil {
		return "", err
	}

	// Attempt to find Tag 57 (which contains PAN, expdate)
	tag57 := bertlvs.FindFirstWithTag(bertlv.NewOneByteTag(byte(0x57)))
	// log.Print(tag57)

	if tag57 == nil {
		return "", errors.New("Could not find Tag 57")
	}

	// Perform the actual masking here
	//TODO JTE is there a way to assign to a range of the slice? tag57.value[3:6] = 0x00\0x00\0x00
	for i := 3; i < 6; i++ {
		tag57.Value[i] = byte(0x00)
	}

	// Update the tlvs with this new value of Tag57
	var updatedTags bertlv.BerTLVs
	updatedTags = append(updatedTags, *tag57)
	for _, tlv := range bertlvs {
		if !bytes.Equal(tlv.Tag, bertlv.NewOneByteTag(byte(0x57))) {
			updatedTags = append(updatedTags, tlv)
		}

	}
	return strings.ToUpper(hex.EncodeToString(updatedTags.Bytes())), nil
}

// Returns the decryption key (KBEK) from the provided KBPK and TR-31 key block
func GetDecryptionKeyFromKeyblock(KBPK []byte, tr31KeyblockString string) (cipher.Block, error) {

	// Derive KBEK and KBAK from KBPK
	KBEKbytes, _, err := DeriveKeyblockKeys(KBPK)
	if err != nil {
		return nil, err
	}

	// Create a decrypter based on the KBEK
	KBEK, err := aes.NewCipher(KBEKbytes)
	if err != nil {
		return nil, err
	}

	// Extract the IV and encrypted key from the TR-31 key block
	keyBlockIv := ivFromTR31KeyBlock(tr31KeyblockString)
	encryptedKeyBytes := encryptedKeyFromTR31KeyBlock(tr31KeyblockString)

	// Decrypt (in-place) the key using the extracted IV and the derived KBEK
	cbc := cipher.NewCBCDecrypter(KBEK, keyBlockIv)
	cbc.CryptBlocks(encryptedKeyBytes, encryptedKeyBytes)

	// At this point, encryptedKeyBytes contains:
	//  2 bytes of length
	// 16 bytes of decrypted key
	// 14 bytes of padding

	length := binary.BigEndian.Uint16(encryptedKeyBytes[0:2])
	fmt.Println("Key length is", length)

	// Convert the decrypted key bytes into the one-time use decryption key
	oneTimeKeyBytes := encryptedKeyBytes[2 : length/8+2] // skip the length bytes and padding
	oneTimeKey, err := aes.NewCipher(oneTimeKeyBytes)

	return oneTimeKey, err
}

func DecryptTTPCipherText(KBEK cipher.Block, ivString string, cipherTextString string) ([]byte, error) {

	// Load the supplied cipherText IV that was in the TTP blob
	cipherTextIV, _ := b64.StdEncoding.DecodeString(ivString)

	// Load the supplied cipherText that was in the TTP blob
	cipherTextBytes, _ := b64.StdEncoding.DecodeString(cipherTextString)

	// Create a decrypter using the one-time key and ciphertext IV
	cbc2 := cipher.NewCBCDecrypter(KBEK, cipherTextIV)
	cbc2.CryptBlocks(cipherTextBytes, cipherTextBytes)

	dst := make([]byte, hex.EncodedLen(len(cipherTextBytes)))
	hex.Encode(dst, cipherTextBytes)

	return dst, nil
}

// Decodes the supplied string of hex digits into bytes and then formats as EMV TLV tags
func dumpTLV(tlvString string) error {

	tlvBytes, _ := hex.DecodeString(tlvString)
	bertlvs, err := bertlv.Parse(tlvBytes)

	if err != nil {
		return err
	}

	for _, tlv := range bertlvs {
		fmt.Printf("%X %X\n", tlv.Tag, tlv.Value)
	}

	return nil
}

/*
[57134761739001010119D22122011143804400000F 82022000 8407A0000000031010 95050000000000 9A03210916 9C0100 5F2A020840 5F340101 9F0206000000003240 9F0306000000000000 9F100706010A03A00000 9F1A020840 9F1E086365613935633065 9F2608B0AAC2EA6FD42409 9F270180 9F34033F0000 9F350121 9F36020433 9F37049EEC7756 9F6E0420700080]
*/
