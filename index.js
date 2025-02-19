import express from "express";
import crypto from "crypto";

function base64StringToArrayBuffer(b64str) {
  const buffer = Buffer.from(b64str, "base64");
  return buffer;
}

function arrayBufferToBase64String(arrayBuffer) {
  return arrayBuffer.toString("base64");
}

function textToArrayBuffer(str) {
  const buf = Buffer.from(str, "utf-8");
  return buf;
}

async function encryptData(encReq, publicKey) {
  const publicKeyBuffer = base64StringToArrayBuffer(publicKey);

  const key = crypto.createPublicKey({
    key: publicKeyBuffer,
    format: "der",
    type: "spki",
  });

  const encReqBuffer = textToArrayBuffer(JSON.stringify(encReq));

  const encryptedData = crypto.publicEncrypt(
    {
      key: key,
      oaepHash: "sha256",
    },
    encReqBuffer
  );

  let encBase64req = arrayBufferToBase64String(encryptedData);

  encBase64req = encBase64req
    .replace(/\+/g, "0plus9")
    .replace(/=/g, "0equal9")
    .replace(/\//g, "0slash9");

  return encBase64req;
}

const app = express();
app.use(express.json());

app.post("/encrypt", async (req, res) => {
  try {
    const { encReq, publicKey } = req.body;

    console.log(publicKey);
    if (!encReq || !publicKey) {
      return res.status(400).json({ error: "Missing encReq or publicKey" });
    }

    const encryptedData = await encryptData(encReq, publicKey);

    res.json({ encryptedData });
  } catch (error) {
    console.error("Error encrypting data:", error);
    res.status(500).json({ error: "Encryption failed" });
  }
});

app.listen(6666, () => {
  console.log("Server is running on port 6666");
});
