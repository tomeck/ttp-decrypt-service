package main

// The following structure is the request payload for this service's /decrypt endpoint
type DecryptRequest struct {
	PaymentCardData string `json:"paymentCardData" validate:"required"`
}

// The following structure is the response for this service's /decrypy endpoint
type DecryptResponse struct {
	EMVData     string             `json:"emvData" validate:"required"`
	ÇardDetails []CardDetailsBlock `json:"cardDetails" validate:"required"`
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
	CardClass              string `json:"cardClass" validate:"required"`
}

type CardInfoResponse struct {
	CardDetailsBlock []CardDetailsBlock `json:"cardDetails" validate:"required"`
}
