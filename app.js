const express = require("express");
const cors = require("cors");
const { createPool } = require("mysql");
const app = express();
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const forge = require("node-forge");
const bodyParser = require("body-parser");
const crypto = require("crypto");

app.use(cors());
app.use(express.json());

const JWT_SECRET = "jedikey";
const crlFilePath = path.join(__dirname, "crl.json");

const con = createPool({
  host: "cerdatabase.cnue620m87uo.ap-southeast-2.rds.amazonaws.com",
  user: "admin",
  password: "admin123",
  database: "cerdatabase",
  port: "3306",
  multipleStatements: true,
});

// INITIAL
app.get("/", (req, res) => {
  console.log("hello");
  con.query("select * from cer", (e, r, f) => {
    if (e) {
      return console.log(e);
    }
    result = r;
    return console.log(r);
  });
  res.status(200).send("HELLO");
});

// LOGIN
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  con.query(
    "SELECT * FROM user WHERE username = ?",
    [username],
    (error, results) => {
      if (error) {
        console.error("Database error:", error);
        return res.status(500).send("Error during database query");
      }

      if (results.length === 0) {
        return res.status(401).send("No user found with the given ID");
      }

      const user = results[0];

      if (user.password !== password) {
        return res.status(401).send("Password does not match");
      }
      console.log({ id: user.id, username: user.username });

      const token = jwt.sign(
        { id: user.id, username: user.username, state: user.state },
        JWT_SECRET,
        {
          expiresIn: "2h",
        }
      );

      res.status(200).send({ token: token });
    }
  );
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// certificate
app.post("/generate-certificate", (req, res) => {
  try {
    const csrPem = req.body.csrPem;
    if (!csrPem) {
      return res.status(400).send({ error: "No CSR provided" });
    }

    const certificatePem = createCertificateFromCSR(csrPem);
    res.send({ certificate: certificatePem });
  } catch (error) {
    console.error("Error processing the CSR:", error);
    res.status(500).send({ error: "Failed to process the CSR" });
  }
});

function createCertificateFromCSR(csrPem) {
  const csr = forge.pki.certificationRequestFromPem(csrPem);
  if (!csr.verify()) {
    throw new Error("Invalid CSR");
  }
  const keys = forge.pki.rsa.generateKeyPair(512);

  let cert = forge.pki.createCertificate();
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.publicKey = keys.publicKey;
  cert.setSubject([
    { shortName: "CN", value: "PeaceKeeper" },
    { shortName: "O", value: "BanchangPki" },
    { shortName: "OU", value: "Secure Division" },
  ]);
  cert.setIssuer(csr.subject.attributes);

  cert.sign(keys.privateKey);
  console.log("generate certificate success");

  return forge.pki.certificateToPem(cert);
}

app.get("/key/:id", authenticateToken, (req, res) => {
  const userId = req.params.id;
  const query = "SELECT publicKey, privateKey FROM user WHERE id = ?";

  con.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error retrieving data:", err);
      return res.status(500).send("Failed to retrieve data");
    }

    if (results.length > 0) {
      const user = results[0];
      res.json({
        publicKey: user.publicKey,
        privateKey: user.privateKey,
      });
    } else {
      res.status(404).send("User not found");
    }
  });
});

// REVOKE
app.post("/revoke/:id/:state", async (req, res) => {
  const { id, state } = req.params;
  const certDetails = req.body;
  console.log(
    `Received certificate details for user ID ${id} in state ${state}:`,
    certDetails
  );

  const tableName = getTableName(state);
  if (!tableName) {
    res.status(400).send("Invalid state provided");
    return;
  }

  await new Promise((resolve) => setTimeout(resolve, 60000)); // Wait for one minute

  insertCertDetails(certDetails, id, tableName, res);
});

// FORCE REVOKE
app.post("/force-revoke/:id/:state", (req, res) => {
  const { id, state } = req.params;
  const certDetails = req.body;
  console.log(
    `Received certificate details for user ID ${id} in state ${state}:`,
    certDetails
  );

  const tableName = getTableName(state);
  if (!tableName) {
    res.status(400).send("Invalid state provided");
    return;
  }

  insertCertDetails(certDetails, id, tableName, res);
});

function getTableName(state) {
  switch (state) {
    case "northern":
      return "northern";
    case "southern":
      return "southern";
    case "northeaster":
      return "northeaster";
    case "central":
      return "central";
    default:
      return null;
  }
}

function insertCertDetails(details, userId, state, res) {
  const { serialNumber, issuer, validFrom, validTo, issuedBy, publicKey } =
    details;

  fs.readFile(crlFilePath, (err, data) => {
    if (err) {
      console.error("Failed to read CRL file:", err);
      res.status(500).send("Failed to read CRL file");
      return;
    }

    let crl = JSON.parse(data);
    const baseIndex = getBaseIndex(state);
    const nextIndex = getNextIndex(crl, baseIndex, baseIndex + 99);

    const certDetails = {
      id: nextIndex,
      user_id: userId,
      serialNumber,
      issuer,
      validFrom,
      validTo,
      issuedBy,
      publicKey,
      state,
    };

    crl.push(certDetails);
    crl.sort((a, b) => a.id - b.id); // Sort by id

    fs.writeFile(crlFilePath, JSON.stringify(crl, null, 2), (err) => {
      if (err) {
        console.error("Failed to write CRL file:", err);
        res.status(500).send("Failed to write CRL file");
        return;
      }

      console.log("Inserted certificate details with ID:", nextIndex);
      res.status(200).send("Certificate details received successfully");
    });
  });
}

function getBaseIndex(state) {
  switch (state) {
    case "northern":
      return 1;
    case "southern":
      return 101;
    case "northeaster":
      return 201;
    case "central":
      return 301;
    default:
      return 0;
  }
}

function getMaxIndex(state) {
  switch (state) {
    case "northern":
      return 100;
    case "southern":
      return 200;
    case "northeaster":
      return 300;
    case "central":
      return 400;
    default:
      return 0;
  }
}

function getNextIndex(crl, minIndex, maxIndex) {
  let currentMax = minIndex - 1;

  for (let i = minIndex; i <= maxIndex; i++) {
    const cert = crl.find((cert) => cert.id === i);
    if (cert && cert.id > currentMax) {
      currentMax = cert.id;
    }
  }

  return currentMax + 1;
}

// GET REVOKE
app.get("/getrevoke/:id/:state", (req, res) => {
  const { id, state } = req.params;

  fs.readFile(crlFilePath, (err, data) => {
    if (err) {
      console.error("Failed to read CRL file:", err);
      res.status(500).send("Failed to read CRL file");
      return;
    }

    const crl = JSON.parse(data);
    const baseIndex = getBaseIndex(state);
    const maxIndex = getMaxIndex(state);

    const certDetails = [];
    for (let i = baseIndex; i <= maxIndex; i++) {
      const cert = crl.find((cert) => cert.id === i && cert.user_id == id);
      if (cert) {
        certDetails.push(cert);
      }
    }

    if (certDetails.length > 0) {
      res.status(200).json(certDetails);
    } else {
      res
        .status(404)
        .send("No certificate details found for the given user ID and state");
    }
  });
});

// Start the server
const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
