const { expect } = require("chai");

const { Redsys } = require("../src/api-redsys");
const requestParams = require("./data/request.json");
const responseParams = require("./data/response.json");
const settings = require("./data/settings.json");

describe("Node Redsys API tests", () => {
  before(() => {
    this.redsys = new Redsys();
  });

  describe("3DES encrypt/decrypt", () => {
    const encryptedText = "Lr6bLJYWKrk=";
    it("Encrypt Merchant order with 3DES in cbc mode", () => {
      const merchantOrder = requestParams.DS_MERCHANT_ORDER;
      expect(this.redsys.encrypt3DES(merchantOrder, settings.key))
        .to.be.equals(encryptedText);
    });
    it("Decrypt Merchant order with 3DES in cbc mode", () => {
      expect(this.redsys.decrypt3DES(encryptedText, settings.key))
        .to.be.equals(requestParams.DS_MERCHANT_ORDER);
    });
  });

  describe("SHA256 algorithm", () => {
    const params = "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4ODEiLCJEU19NRVJDSEFOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5TQUNUSU9OVFlQRSI6IjAiLCJEU19NRVJDSEFOVF9URVJNSU5BTCI6Ijg3MSIsIkRTX01FUkNIQU5UX01FUkNIQU5UVVJMIjoiIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiIiLCJEU19NRVJDSEFOVF9VUkxLTyI6IiJ9";
    const signature = "3TEI5WyvHf1D/whByt1ENgFH/HPIP9UFuB6LkCYgj+E=";
    const encryptedKey = "Lr6bLJYWKrk=";

    it("Apply SHA256", () => {
      expect(this.redsys.mac256(params, encryptedKey))
        .to.be.equals(signature);
    });
  });

  describe("Manage Merchant Parameters", () => {
    const decodedParams = {
      Ds_Date: "09/11/2015",
      Ds_Hour: "18:03",
      Ds_SecurePayment: "0",
      Ds_Card_Country: "724",
      Ds_Amount: "145",
      Ds_Currency: "978",
      Ds_Order: "0069",
      Ds_MerchantCode: "999008881",
      Ds_Terminal: "871",
      Ds_Response: "0000",
      Ds_MerchantData: "",
      Ds_TransactionType: "0",
      Ds_ConsumerLanguage: "1",
      Ds_AuthorisationCode: "082150",
    };

    it("Create Merchant Parameters", () => {
      // Create a temporary request params object without the DCC fields for this test
      const tempRequestParams = { ...requestParams };
      delete tempRequestParams.Ds_Card_Country;
      delete tempRequestParams.Ds_Currency_DCC;
      delete tempRequestParams.Ds_CurrencyName_DDC;
      delete tempRequestParams.Ds_Markup_DDC;
      delete tempRequestParams.Ds_Amount_DCC;
      delete tempRequestParams.Ds_ExchangeRate_DDC;
      const expectedParams = "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4ODEiLCJEU19NRVJDSEFOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5TQUNUSU9OVFlQRSI6IjAiLCJEU19NRVJDSEFOVF9URVJNSU5BTCI6Ijg3MSIsIkRTX01FUkNIQU5UX01FUkNIQU5UVVJMIjoiIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiIiLCJEU19NRVJDSEFOVF9VUkxLTyI6IiJ9";
      expect(this.redsys.createMerchantParameters(tempRequestParams))
        .to.be.equals(expectedParams);
    });

    it("Decode Merchant Parameters", () => {
      const merchantParameters = responseParams.Ds_MerchantParameters;
      expect(this.redsys.decodeMerchantParameters(merchantParameters))
        .to.be.deep.equals(decodedParams);
    });
  });

  describe("Manage Merchant Signature", () => {
    it("Create Merchant Signature", () => {
      const signature = "54OFTrdjJuDZ8DO/5L61TN4xRec5vz1el4So7VStxXY=";
      expect(this.redsys.createMerchantSignature(settings.key, requestParams))
        .to.be.equals(signature);
    });

    it("Create Merchant Signature Notification", () => {
      const merchantSignatureNotif = `${this.redsys.createMerchantSignatureNotif(
        settings.key, responseParams.Ds_MerchantParameters,
      )}=`;
      expect(merchantSignatureNotif).to.be.equals(responseParams.Ds_Signature);
    });

    it("Merchant Signature Is Valid", () => {
      const signature = responseParams.Ds_Signature;
      const expectedSignature = "6DVpRPAPoChZh2cgaWnLqlfFsKeXdRfAO_tz-UrxJcU";
      expect(this.redsys.merchantSignatureIsValid(signature, expectedSignature))
        .to.be.equals(true);
    });
  });
});
