//
// Created by Antonia Januszewicz on 1/4/26.
//
#include "../include/server.h"

// constructor
Server::Server(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam){
    cc = ccParam;
    pk = pkParam;
    k = vectorParam;

}

// 2. Compute Similarity Scores
bool Server::computeSimilarity() {
    return false;
}

// 3. Compute Threshold
bool Server::computeThreshold() {
    return false;
}

// 4. Database Query
//=========== NOT NEEDED IF USING PLAINTEXT ===========
bool Server::databaseQuery() {

    if (databaseCipher.empty()) {
        cerr << "Error: database not loaded" << endl;
        return false;
    }

    queryResult.clear();
    size_t batchSize = cc->GetEncodingParams()->GetBatchSize();


    for (size_t i = 0; i < databaseCipher.size(); i++) {

        vector<Ciphertext<DCRTPoly>>& dbItem = databaseCipher[i];

        for (size_t bitIdx = 0; bitIdx < dbItem.size(); bitIdx++) {

            vector<double> maskVec(batchSize, 0.0);
            maskVec[i] = 1.0;
            Plaintext mask = cc->MakeCKKSPackedPlaintext(maskVec);

            Ciphertext<DCRTPoly> extractedSlot = cc->EvalMult(queryCipher, mask);
            cc->RelinearizeInPlace(extractedSlot);
            cc->RescaleInPlace(extractedSlot);
            Ciphertext<DCRTPoly> product = cc->EvalMult(extractedSlot, dbItem[bitIdx]);
            cc->RelinearizeInPlace(product);
            cc->RescaleInPlace(product);
            Ciphertext<DCRTPoly> summed = OpenFHEWrapper::sumAllSlots(cc, product);


            queryResult.push_back(summed);
        }
    }
    return true;

}

// 5. Format and Return Query Result
bool Server::saveResult() {

    if (queryResult.empty()) {
        cerr << "Error: No results to save" << endl;
        return false;
    }

    cout << "Query result ready to send to client (" << queryResult.size() << " ciphertexts)" << endl;

    return true;

}



// takes binary vector
// converts to encrypted ciphertext
// stores in databaseCipher for databaseQuery to use
//=========== NOT NEEDED IF USING PLAINTEXT ===========
bool Server::loadAndEncryptBinaryDatabase(const vector<vector<int>>& binaryStrings) {

    databaseCipher.clear();

    for (const auto& binaryVec : binaryStrings)
    {
        vector<Ciphertext<DCRTPoly>> encryptedBits;
        for (int bit : binaryVec) {

            vector<double> doubleVec(k, 0.0);
            doubleVec[0] = static_cast<double>(bit);
            Ciphertext<DCRTPoly> encrypted = OpenFHEWrapper::encryptFromVector(cc, pk, doubleVec);
            encryptedBits.push_back(encrypted);

        }

        databaseCipher.push_back(encryptedBits);
    }
}

// (ciphertext x plaintext change)
void Server::loadPlaintextDatabase(const vector<vector<int>>& binaryStrings) {
    plaintextDatabase.clear();
    size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    
    for (const auto& binaryVec : binaryStrings) {
        vector<double> packedVec(batchSize, 0.0);
        for (size_t i = 0; i < binaryVec.size(); i++) {
            packedVec[i] = static_cast<double>(binaryVec[i]);
        }

        Plaintext plainPt = cc->MakeCKKSPackedPlaintext(packedVec);
        plaintextDatabase.push_back(plainPt);
    }
}

// uses plaintext database (ciphertext x plaintext) and precreated selectors
Ciphertext<DCRTPoly> Server::databaseQueryPlain(const vector<Ciphertext<DCRTPoly>>& selectors) {
    if (plaintextDatabase.empty() || selectors.size() != plaintextDatabase.size())
    {
        return Ciphertext<DCRTPoly>();
    }
    Ciphertext<DCRTPoly> accumulator = cc->EvalMult(selectors[0], plaintextDatabase[0]);
    cc->RescaleInPlace(accumulator);

    for (size_t i = 1; i < plaintextDatabase.size(); i++)
    {
        auto term = cc->EvalMult(selectors[i], plaintextDatabase[i]);
        cc->RescaleInPlace(term);
        accumulator = cc->EvalAdd(accumulator, term);
    }
    
    return accumulator;
}


//get queryResult
vector<Ciphertext<DCRTPoly>> Server::getQueryResult() {
    return queryResult;
}