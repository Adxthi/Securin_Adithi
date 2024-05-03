const express = require('express');
const { fetchDataFromMongoDB, fetchCVEDetailsFromMongoDB } = require('./db');

const app = express();
const port = 3000;

app.use(express.static('public'));

app.get('/cve-data', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const resultsPerPage = parseInt(req.query.resultsPerPage) || 10;
        const data = await fetchDataFromMongoDB(page, resultsPerPage);
        res.json(data);
    } catch (error) {
        console.error('Error fetching CVE data:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/cve-details', async (req, res) => {
    try {
        const cveId = req.query.id;
        const details = await fetchCVEDetailsFromMongoDB(cveId);
        res.json(details);
    } catch (error) {
        console.error('Error fetching CVE details:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
