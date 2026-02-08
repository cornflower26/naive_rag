//
// Created by Antonia Januszewicz on 1/4/26.
//
#include "../include/client.h"

// 1. Take in Client query
Client::Client(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
        PrivateKey<DCRTPoly> skParam, size_t vectorParam, string query){

}

// 2. Compute Client embedding
vector<float_t> Client::embedQuery(std::string q) {
    return {0};
}

// 3. Send Client embedded query
bool Client::sendClientEmbedding() {
    return false;
}

// 4. Receive query result
vector<size_t> Client::receiveQueryResult() {
    return {0};
}

// 5. Return final result
vector<std::string> Client::decodeFinalResult() {
    return {""};
}
