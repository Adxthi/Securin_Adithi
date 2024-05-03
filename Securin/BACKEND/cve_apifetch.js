const axios = require('axios');
const { MongoClient } = require('mongodb');

// Function to fetch data from the API
async function fetchCveData(startIndex, resultsPerPage) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=${startIndex}&resultsPerPage=${resultsPerPage}`;
    try {
        const response = await axios.get(url);
        const data = response.data;
        return { vulnerabilities: data.vulnerabilities, resultsPerPage: data.resultsPerPage, totalResults: data.totalResults };
    } catch (error) {
        console.error(`Failed to fetch data from the API for startIndex=${startIndex}.`, error.message);
        return { vulnerabilities: [], resultsPerPage: 0, totalResults: 0 };
    }
}

// Function to insert data into MongoDB
async function insertData(client, cveData) {
    const db = client.db("cve_securin_db");
    const collection = db.collection("cve");
    try {
        if (cveData.length > 0) { // Check if data is not empty before insertion
            await collection.insertMany(cveData);
            console.log(`Inserted ${cveData.length} records.`);
        }
    } catch (error) {
        console.error('Error inserting data into MongoDB:', error);
    }
}

// Main function
async function main() {
    const client = new MongoClient("mongodb://localhost:27017/");
    try {
        await client.connect();
        let start_index = 0;
        const results_per_page = 2000;
        let total_results = null;

        while (total_results === null || start_index < total_results) {
            const { vulnerabilities, resultsPerPage: fetchedResults, totalResults: fetchedTotal } = await fetchCveData(start_index, results_per_page);
            total_results = fetchedTotal;
            await insertData(client, vulnerabilities);
            start_index += fetchedResults;
            console.log(`Progress: ${start_index}/${total_results}`);
        }
        console.log("Data stored successfully.");
    } catch (error) {
        console.error('Error:', error);
    } finally {
        await client.close();
    }
}

main();
