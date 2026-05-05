//
// Created by Antonia Januszewicz on 1/4/26.
//

#ifndef NAIVE_RAG_CLIENT_H
#define NAIVE_RAG_CLIENT_H

// ** client: made up of 3 general functions
// 1. Take in Client query
// 2. Compute Client embedding
// 3. Send Client embedded query
// 4. Receive query result
// 5. Return final result

#pragma once

#include "../include/config.h"
#include "../include/openFHE_wrapper.h"
#include "../include/vector_utils.h"
#include "openfhe.h"
#include <vector>
//#include <omp.h>
#include <ctime>
#include <fstream>

using namespace lbcrypto;
using namespace std;

class Client {
public:
    // constructor
    // 1. Take in Client query
    Client(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
             PrivateKey<DCRTPoly> skParam, size_t vectorParam, string query="");

    // destructor
    ~Client() = default;

    inline bool setQuery(string new_query) {query = new_query; return true;};
    inline bool setQueryEmbedding(vector<float> embedding) {embeddedQuery = embedding; return true;};

    inline string returnQuery() {return query;};
    inline vector<string> returnQueryResult() {return queryResult;};

    inline Ciphertext<DCRTPoly> getEncryptedQuery() { return encryptedQuery; }

    // 2. Compute Client embedding
    vector<float_t> embedQuery(std::string q);

    // 3. Send Client embedded query
    bool sendClientEmbedding();

    // 4. Receive query result
    vector<size_t> receiveQueryResult();

    // 5. Return final result
    vector<std::string> decodeFinalResult();

protected:
    // protected members (accessible by derived classes)
    string query;
    vector<float> embeddedQuery;
    vector<string> queryResult;
    vector<Ciphertext<DCRTPoly>> encryptedResult;

    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;
    size_t k;

    Ciphertext<DCRTPoly> encryptedResult;

};

#endif //NAIVE_RAG_CLIENT_H
