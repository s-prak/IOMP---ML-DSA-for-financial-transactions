import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import JwsSignerQ from './signer.mjs';
import JwsValidatorQ from './validator.mjs';
import crypto from 'crypto'; 

const app = express();
const port = 3000;

// Mock payee account data for signature verification
const payeeAccounts = {
    'Robert Downey': '9876543210',
    'Tony Stark': '1231231234',
    'Stephen Hawkins': '4564564567'
};

// Serve static files from the "public" directory and parse request bodies
app.use(express.static(path.join(path.resolve(), 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); 

// Serve the main HTML page on a GET request
app.get('/', (req, res) => {
    res.sendFile(path.join(path.resolve(), 'index.html'));
});

// Generate cryptographic keys using a random seed
const seed = new Uint8Array(32); 
crypto.getRandomValues(seed);
const keys = ml_dsa65.keygen(seed);

let requestOptions; // Stores request details for later validation

// Endpoint to generate a digital signature
app.post('/generate-signature', (req, res) => {
    console.log("in generate signature");
    
    const config_sign = { signingKey: keys.secretKey };

    // Setup request options with transaction details and headers
    requestOptions = {
        body: { amount: req.body.amount },
        date : Date.now(),
        headers: {
            'fspiop-source': req.body.source,
            'fspiop-destination': req.body.destination,
        }
    };

    // Create signer and sign the request
    let jwsSignerQ = new JwsSignerQ(config_sign);
    jwsSignerQ.sign(requestOptions);
    console.log(requestOptions);

    // Send signature if generated, otherwise error
    if ('fspiop-signature' in requestOptions.headers) {
        const base64String = Buffer.from(requestOptions.headers['fspiop-signature'].signature).toString('base64');
        console.log(base64String);
        res.json({ message: "SIGNATURE GENERATED!!", signature: base64String });
    } else {
        res.status(400).json({ message: "Error in generating signature" });
    }
});

// Endpoint to validate the digital signature
app.post('/validate-signature', (req, res) => {
    console.log("in validate signature");

    const config_validate = {
        validationKeys: { '1234567890': keys.publicKey }
    };

    // Setup request object for validation with signature and details
    const request = {
        body: { amount: req.body.validateAmount },
        date: requestOptions.date,
        headers: {
            'fspiop-source': "1234567890",
            'fspiop-destination': payeeAccounts[req.body.validateBeneficiary],
            'fspiop-signature': requestOptions.headers['fspiop-signature']
        }
    };

    // Create validator and validate the request
    let jwsValidatorQ = new JwsValidatorQ(config_validate);
    jwsValidatorQ.validate(request);
    const isValid = request.headers['result'];
    console.log(request);
    console.log(requestOptions);

    // Send validation result
    res.json({ validationResult: isValid ? "Signature is valid!!!" : "Signature is invalid:((" });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
