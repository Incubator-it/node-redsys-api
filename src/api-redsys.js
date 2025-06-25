// TODO Refactor and remove class in 1.0.0 version
/* eslint-disable class-methods-use-this */
const crypto = require("crypto");
const base64url = require("base64url");

const { zeroPad, zeroUnpad } = require("./utils");

class Redsys {
  encrypt3DES(str, key) {
    const secretKey = Buffer.from(key, "base64");
    const iv = Buffer.alloc(8, 0);
    const cipher = crypto.createCipheriv("des-ede3-cbc", secretKey, iv);
    cipher.setAutoPadding(false);
    return (
      cipher.update(zeroPad(str, 8), "utf8", "base64") + cipher.final("base64")
    );
  }

  decrypt3DES(str, key) {
    const secretKey = Buffer.from(key, "base64");
    const iv = Buffer.alloc(8, 0);
    const cipher = crypto.createDecipheriv("des-ede3-cbc", secretKey, iv);
    cipher.setAutoPadding(false);
    const res = cipher.update(zeroUnpad(str, 8), "base64", "utf8") + cipher.final("utf8");
    return res.replace(/\0/g, "");
  }

  mac256(data, key) {
    return crypto
      .createHmac("sha256", Buffer.from(key, "base64"))
      .update(data)
      .digest("base64");
  }

  createMerchantParameters(data) {
    return Buffer.from(JSON.stringify(data), "utf8").toString("base64");
  }

  decodeMerchantParameters(data) {
    return this.parmsToObject(JSON.parse(base64url.decode(data, "utf8")));
  }

  /**
   * Safely decode URI components with fallback handling for malformed encoding
   * @param {string} value - The value to decode
   * @returns {string} - The decoded value or original if decoding fails
   */
  safeDecodeURIComponent(value) {
    if (typeof value !== "string") {
      return value;
    }

    try {
      return decodeURIComponent(value);
    } catch (error) {
      if (error.message.includes("URI malformed")) {
        // Handle common malformed URI cases
        let fixedValue = value;

        // Fix standalone % symbols (like "3.95%" -> "3.95%25")
        fixedValue = fixedValue.replace(/%(?![0-9A-Fa-f]{2})/g, "%25");

        // Fix incomplete percent encodings (like "%a" -> "%25a")
        fixedValue = fixedValue.replace(
          /%([0-9A-Fa-f](?![0-9A-Fa-f]))/g,
          "%25$1",
        );

        // Fix invalid percent encodings (like "%zz" -> "%25zz")
        fixedValue = fixedValue.replace(
          /%([^0-9A-Fa-f][^0-9A-Fa-f])/g,
          "%25$1",
        );

        try {
          return decodeURIComponent(fixedValue);
        } catch (retryError) {
          // If it still fails, return the original value
          return value;
        }
      } else {
        // For other types of errors, return original value
        return value;
      }
    }
  }

  parmsToObject(data) {
    const res = {};
    Object.keys(data).forEach((param) => {
      // Safely decode the parameter name
      const decodedParam = this.safeDecodeURIComponent(param);

      if (typeof data[param] === "object" && data[param] !== null) {
        // Handle nested objects recursively
        res[decodedParam] = this.parmsToObject(data[param]);
      } else {
        // Safely decode the parameter value
        const decodedValue = this.safeDecodeURIComponent(data[param]);

        // Check if the decoded value indicates it was an object that got stringified
        if (decodedValue === "[object Object]") {
          res[decodedParam] = this.parmsToObject(data[param]);
        } else {
          res[decodedParam] = decodedValue;
        }
      }
    });
    return res;
  }

  createMerchantSignature(key, data) {
    const merchantParameters = this.createMerchantParameters(data);
    const orderId = data.Ds_Merchant_Order || data.DS_MERCHANT_ORDER;
    const orderKey = this.encrypt3DES(orderId, key);

    return this.mac256(merchantParameters, orderKey);
  }

  createMerchantSignatureNotif(key, data) {
    const merchantParameters = this.decodeMerchantParameters(data);
    const orderId = merchantParameters.Ds_Order || merchantParameters.DS_ORDER;
    const orderKey = this.encrypt3DES(orderId, key);

    const res = this.mac256(data, orderKey);
    return base64url.encode(res, "base64");
  }

  merchantSignatureIsValid(signA, signB) {
    return (
      base64url.decode(signA, "base64") === base64url.decode(signB, "base64")
    );
  }
}

module.exports = {
  Redsys,
};
