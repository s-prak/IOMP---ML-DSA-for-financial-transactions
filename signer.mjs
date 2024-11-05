import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import safeStringify from 'fast-safe-stringify';


class JwsSignerQ{

    constructor(config){
        this.logger = console;

        if(!config.signingKey) {
            throw new Error('Signing key must be supplied as config argument');
        }

        this.alg = 'ml_dsa65';

        this.signingKey = config.signingKey;
        //console.log(this.signingKey);
    }

    sign(requestOptions){
        const payload = safeStringify(requestOptions.body) || safeStringify(requestOptions.data);
        this.logger.isDebugEnabled && this.logger.debug(`JWS Signing request: ${safeStringify(requestOptions)}`);

        if(!payload) {
            throw new Error('Cannot sign with no body');
        }

        // get the signature and add it to the header
        requestOptions.headers['fspiop-signature'] = this.getSignature(requestOptions);

        if (requestOptions.body && typeof requestOptions.body !== 'string') {
            requestOptions.body = safeStringify(requestOptions.body);
        }
        if (requestOptions.data && typeof requestOptions.data !== 'string') {
            requestOptions.data = safeStringify(requestOptions.data);
        }

    }

    getSignature(requestOptions){
        this.logger.isDebugEnabled && this.logger.debug(`Get JWS Signature: ${safeStringify(requestOptions)}`);
        const payload = safeStringify(requestOptions.body) || safeStringify(requestOptions.data);

        if(!payload) {
            throw new Error('Cannot sign with no body');
        }

        // Note: Property names are case sensitive in the protected header object even though they are
        // not case sensitive in the actual HTTP headers
        const headerObject = {
            alg: this.alg,
            'FSPIOP-URI': requestOptions.headers['fspiop-uri'],
            'FSPIOP-Source': requestOptions.headers['fspiop-source']
        };

        // set destination in the protected header object if it is present in the request headers
        if (requestOptions.headers['fspiop-destination']) {
            headerObject['FSPIOP-Destination'] = requestOptions.headers['fspiop-destination'];
        }

        // set date in the protected header object if it is present in the request headers
        if (requestOptions.headers['date']) {
            headerObject['Date'] = requestOptions.headers['date'];
        }

        const token = ml_dsa65.sign(this.signingKey, payload);
        //console.log(requestOptionsString);
        //console.log(token);
        //console.log(safeStringify(token));
        //console.log(safeStringify(requestOptions));

        const signatureObject = {
            signature : token, 
            headers : headerObject
        }
        console.log(signatureObject.signature);
        global.signatureObject = signatureObject;
        return signatureObject;
        
    }
}

export default JwsSignerQ;