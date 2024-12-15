# IOMP-ML-DSA-for-financial-transactions

Authentication of transactions using ML-DSA, post quantum authentication algorithm <br>

This project proposes implementing ML-DSA (Module Lattice Digital Signature Algorithm) as a quantum-resistant solution for securing digital transactions within a payment gateway framework. ML-DSA is a post-quantum cryptographic signature scheme designed to protect data integrity and authenticate transactions in a world where quantum computers could potentially break traditional cryptographic algorithms. Incorporating ML-DSA creates a system that remains secure against both classical and quantum computing threats, ensuring that each transaction is signed and validated with post-quantum resilience. <br>

The proposed solution involves generating and verifying ML-DSA signatures at the server end. During a transaction, a signature is generated based on key data (such as payer and payee accounts and the transaction amount). This signature is accessible to the backend, where the ML-DSA verify algorithm verifies it, ensuring that the data has not been tampered with. <br>

This approach enhances the payment gateway’s robustness against quantum attacks. Implementing this proof of concept aims to evaluate ML-DSA’s viability as a standardized quantum-resistant solution that can be seamlessly integrated into financial systems and other critical applications vulnerable to future quantum threats.

## Step 1

Start the server running `node src/server.mjs` on the terminal

## Step 2

On the web browser open the url `http://localhost:3000`
