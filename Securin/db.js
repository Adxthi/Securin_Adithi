const express = require("express");
const { MongoClient } = require("mongodb");
const { exec } = require("child_process");
const app = express();
const port = 4000;

const url = "mongodb://localhost:27017";
const dbName = "cve_securin_db";

app.use(express.static("public"));

async function fetchDataFromMongoDB(page, resultsPerPage) {
  const client = new MongoClient(url);

  try {
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection("cve");
    const data = await collection
      .find({})
      .skip((page - 1) * resultsPerPage)
      .limit(resultsPerPage)
      .toArray();
    return data.map((entry) => ({
      cve_id: entry.cve.id,
      identifier: entry.cve.sourceIdentifier,
      published_date: entry.cve.published,
      last_modified_date: entry.cve.lastModified,
      status: entry.cve.vulnStatus,
    }));
  } catch (error) {
    console.error("Error fetching data from MongoDB:", error);
    return [];
  } finally {
    await client.close();
  }
}

async function fetchCVEDetailsFromMongoDB(cveId) {
  const client = new MongoClient(url);

  try {
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection("cve");
    const data = await collection.findOne({ "cve.id": cveId });
    return data;
  } catch (error) {
    console.error("Error fetching CVE details from MongoDB:", error);
    return {};
  } finally {
    await client.close();
  }
}

app.get("/cve-data", async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const resultsPerPage = parseInt(req.query.resultsPerPage) || 10;
  const client = new MongoClient(url);

  try {
    await client.connect();
    const db = client.db(dbName);
    const collection = db.collection("cve");
    const totalRecords = await collection.countDocuments({});
    const data = await collection
      .find({})
      .skip((page - 1) * resultsPerPage)
      .limit(resultsPerPage)
      .toArray();
    const responseData = {
      totalRecords,
      data: data.map((entry) => ({
        cve_id: entry.cve.id,
        identifier: entry.cve.sourceIdentifier,
        published_date: entry.cve.published,
        last_modified_date: entry.cve.lastModified,
        status: entry.cve.vulnStatus,
      })),
    };
    res.json(responseData);
  } catch (error) {
    console.error("Error fetching data from MongoDB:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    await client.close();
  }
});

app.get("/cve-details", async (req, res) => {
  const cveId = req.query.id;
  const details = await fetchCVEDetailsFromMongoDB(cveId);
  res.json(details);
});

const server = app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  
    exec(`open http://localhost:${port}`);
  });
  
  server.on("close", () => {
    console.log("Server closed");
  });
