//
// Created by Antonia Januszewicz on 1/4/26.
//

#ifndef NAIVE_RAG_SERVER_H
#define NAIVE_RAG_SERVER_H

// ** server: contains the steps
// 1. Receive Ciphertext
// 2. Compute Similarity Scores
// 3. Compute Threshold
// 4. Retrieve element from database
// 5. Format and Return Query Result

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
//#include <omp.h>
#include <time.h>
#include <ctime>
#include <fstream>

using namespace lbcrypto;
using namespace std;

class Server {
public:
    // constructor
    Server(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam);
    bool loadAndEncryptBinaryDatabase(const vector<vector<int>>& binaryStrings);

    // destructor
    ~Server() = default;

    // 1. Receive Ciphertext
    inline bool setCiphertext(Ciphertext<DCRTPoly> query) { queryCipher = query; return true;};
    inline bool setSquareCiphertext(Ciphertext<DCRTPoly> square) { squareCipher = square; return true;};

    // 2. Compute Similarity Scores
    bool computeSimilarity();

    // 3. Compute Threshold
    bool computeThreshold();

    // 4. Database Query
    bool databaseQuery();

    // 5. Format and Return Query Result
    bool saveResult();

    vector<Ciphertext<DCRTPoly>> getQueryResult();

    void loadPlaintexDatabase(const vector<vector<int>>& binaryStrings);

    Ciphertext<DCRTPoly> databaseQueryOptimized(const vector<Ciphertext<DCRTPoly>>& selectors):


protected:
    // protected members (accessible by derived classes)
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    Ciphertext<DCRTPoly> queryCipher;
    Ciphertext<DCRTPoly> squareCipher;
    vector<Ciphertext<DCRTPoly>> queryResult;

    size_t k;

    vector<Plaintext> plaintextDatabase;
    vector<vector<Ciphertext<DCRTPoly>>> databaseCipher;
};

#endif //NAIVE_RAG_SERVER_H
