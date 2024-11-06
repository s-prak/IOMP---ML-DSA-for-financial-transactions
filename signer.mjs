import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import safeStringify from 'fast-safe-stringify';

class JwsSignerQ {
    constructor(config) {
        this.logger = console;

        // Check if a signing key is provided in the config
        if (!config.signingKey) {
            throw new Error('Signing key must be supplied as config argument');
        }

        // Set the algorithm to be used for signing
        this.alg = 'ml_dsa65';

        this.signingKey = config.signingKey;
    }

    sign(requestOptions) {
        // Safely stringify the request body to create the payload
        const payload = safeStringify(requestOptions.body) || safeStringify(requestOptions.data);
        this.logger.isDebugEnabled && this.logger.debug(`JWS Signing request: ${safeStringify(requestOptions)}`);

        if (!payload) {
            throw new Error('Cannot sign with no body');
        }

        // Get the signature and add it to the request headers
        requestOptions.headers['fspiop-signature'] = this.getSignature(requestOptions);

        // Ensure body and data are stringified if not already strings
        if (requestOptions.body && typeof requestOptions.body !== 'string') {
            requestOptions.body = safeStringify(requestOptions.body);
        }
        if (requestOptions.data && typeof requestOptions.data !== 'string') {
            requestOptions.data = safeStringify(requestOptions.data);
        }
    }

    getSignature(requestOptions) {
        this.logger.isDebugEnabled && this.logger.debug(`Get JWS Signature: ${safeStringify(requestOptions)}`);
        
        // Convert request body to a string if needed for signing
        const payload = safeStringify(requestOptions.body) || safeStringify(requestOptions.data);

        if (!payload) {
            throw new Error('Cannot sign with no body');
        }

        // Create the protected header object, which is case-sensitive
        const headerObject = {
            alg: this.alg,
            'FSPIOP-URI': requestOptions.headers['fspiop-uri'],
            'FSPIOP-Source': requestOptions.headers['fspiop-source']
        };

        // Add optional headers if available in the request
        if (requestOptions.headers['fspiop-destination']) {
            headerObject['FSPIOP-Destination'] = requestOptions.headers['fspiop-destination'];
        }

        if (requestOptions.headers['date']) {
            headerObject['Date'] = requestOptions.headers['date'];
        }

        // Generate the digital signature using ml_dsa65 with the signing key and payload
        const token = ml_dsa65.sign(this.signingKey, payload);

        // Create a signature object with the signature and header information
        const signatureObject = {
            signature: token,
            headers: headerObject
        };

        // Store the signature globally for further processing
        global.signatureObject = signatureObject;
        return signatureObject;
    }
}

export default JwsSignerQ;
