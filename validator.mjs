import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import { sign } from 'crypto';
import safeStringify from 'fast-safe-stringify';

const SIGNATURE_ALGORITHMS = ['ml_dsa65'];

class JwsValidatorQ{

    constructor(config) {
        this.logger = console;

        if(!config.validationKeys) {
            throw new Error('Validation keys must be supplied as config argument');
        }

        this.validationKeys = config.validationKeys;
    }

    validate(request) {
        try{
            const headers= request.headers;
            const payload = safeStringify(request.body) || safeStringify(request.payload);
            
            this.logger.isDebugEnabled && this.logger.debug(`Validating JWS on request with headers: ${safeStringify(headers)} and body: ${safeStringify(payload)}`);

            if(!payload) {
                throw new Error('Cannot validate JWS without a body');
            }

            // first check we have a public (validation) key for the request source
            if(!headers['fspiop-source']) {
                throw new Error('FSPIOP-Source HTTP header not in request headers. Unable to verify JWS');
            }
            

            const pubKey = this.validationKeys[headers['fspiop-source']];
            //console.log('_____________public key validate_______________________');
            //console.log(pubKey);

            if(!pubKey) {
                throw new Error(`JWS public key for '${headers['fspiop-source']}' not available. Unable to verify JWS. Only have keys for: ${safeStringify(Object.keys(this.validationKeys))}`);
            }

            const result=headers['fspiop-signature'];
            //console.log(result);
            const isValid = ml_dsa65.verify(pubKey, payload, result.signature);
            console.log(isValid);

            this._validateProtectedHeader(headers, result.headers);

            this.logger.isDebugEnabled && this.logger.debug(`JWS verify result: ${safeStringify(result)}`);

            this.logger.isDebugEnabled && this.logger.debug(`JWS valid for request ${safeStringify(request)}`);

            request.headers['result']=isValid;

            return isValid;
        }
        catch(err){
            this.logger.isDebugEnabled && this.logger.debug(`Error validating JWS: ${err.stack || safeStringify(err)}`);
            throw err;
        }
        
    }

    /**
     * Validates the protected header and checks it against the actual request headers.
     * Throws an exception if a discrepancy is detected or validation fails.
    */
    _validateProtectedHeader(headers, decodedProtectedHeader) {
        // check FSPIOP-Source is present and matches
        if(!decodedProtectedHeader['FSPIOP-Source']) {
            throw new Error(`Decoded protected header does not contain required FSPIOP-Source element: ${safeStringify(decodedProtectedHeader)}`);
        }
        if(!headers['fspiop-source']) {
            throw new Error(`FSPIOP-Source HTTP header not present in request headers: ${safeStringify(headers)}`);
        }
        if(decodedProtectedHeader['FSPIOP-Source'] !== headers['fspiop-source']) {
            throw new Error(`FSPIOP-Source HTTP request header value: ${headers['fspiop-source']} does not match protected header value: ${decodedProtectedHeader['FSPIOP-Source']}`);
        }


        // if we have a Date field in the protected header it must be present in the HTTP header and the values should match exactly
        if(decodedProtectedHeader['Date'] && !headers['date']) {
            throw new Error(`Date header is present in protected header but not in HTTP request: ${safeStringify(headers)}`);
        }
        if(decodedProtectedHeader['Date'] && (headers['date'] !== decodedProtectedHeader['Date'])) {
            throw new Error(`HTTP date header: ${headers['date']} does not match protected header Date value: ${decodedProtectedHeader['Date']}`);
        }

        // if we have an HTTP fspiop-destination header it should also be in the protected header and the values should match exactly
        if(headers['fspiop-destination'] && !decodedProtectedHeader['FSPIOP-Destination']) {
            throw new Error(`HTTP fspiop-destination header is present but is not present in protected header: ${safeStringify(decodedProtectedHeader)}`);
        }
        if(decodedProtectedHeader['FSPIOP-Destination'] && !headers['fspiop-destination']) {
            throw new Error(`FSPIOP-Destination header is present in protected header but not in HTTP request: ${safeStringify(headers)}`);
        }
        if(headers['fspiop-destination'] && (headers['fspiop-destination'] !== decodedProtectedHeader['FSPIOP-Destination'])) {
            throw new Error(`HTTP FSPIOP-Destination header: ${headers['fspiop-destination']} does not match protected header FSPIOP-Destination value: ${decodedProtectedHeader['FSPIOP-Destination']}`);
        }
    }
        
}

export default JwsValidatorQ;