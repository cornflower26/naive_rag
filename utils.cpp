//
// Created by Antonia Januszewicz on 1/4/26.
//
#include <fstream>
#include <sstream>
#include <stdexcept>

#include <faiss/IndexFlat.h>
#include <faiss/index_io.h>
using namespace std;

static std::vector<float> readFloatsFromFile(const std::string& filename) {
    std::vector<float> result;
    std::ifstream file(filename);

    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }

    std::string line;
    while (std::getline(file, line)) {
        // Remove leading '[' and trailing ']' if present
        if (!line.empty() && line.front() == '[') {
            line = line.substr(1);
        }
        if (!line.empty() && line.back() == ']') {
            line.pop_back();
        }

        std::stringstream ss(line);
        std::string token;

        // Read comma-separated values
        while (std::getline(ss, token, ',')) {
            try {
                float value = std::stof(token);
                result.push_back(value);
            } catch (const std::invalid_argument& e) {
                // Skip invalid values
                continue;
            }
        }
    }

    file.close();
    return result;
}

static std::vector<std::string> readStringsFromFile(const std::string& filename) {
    std::vector<std::string> result;
    std::ifstream file(filename);

    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines
        if (line.empty()) {
            continue;
        }

        // Remove leading/trailing whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");

        if (start == std::string::npos) {
            continue;
        }

        line = line.substr(start, end - start + 1);

        // Remove outer quotes: "['...']"
        // Expected format: "['text']"
        if (line.size() >= 6 &&
            line.substr(0, 3) == "\"['" &&
            line.substr(line.size() - 3) == "']\"") {

            // Extract the content between "[' and ']"
            std::string content = line.substr(3, line.size() - 6);
            result.push_back(content);
        }
    }

    file.close();
    return result;
}

static faiss::Index* readFaissIndex(const std::string& filename) {
    try {
        faiss::Index* index = faiss::read_index(filename.c_str());
        if (!index) {
            throw std::runtime_error("Failed to read FAISS index from file: " + filename);
        }
        //return std::unique_ptr<faiss::Index>(index);
        return index;
    } catch (const std::exception& e) {
        throw std::runtime_error("Error reading FAISS index: " + std::string(e.what()));
    }
}

static std::vector<std::vector<float>> faissIndexToVectors(faiss::Index* index) {
    if (!index) {
        throw std::runtime_error("Index is null");
    }

    int n = index->ntotal;  // number of vectors
    int d = index->d;       // dimension

    std::vector<std::vector<float>> embeddings;
    embeddings.reserve(n);

    // Try to cast to IndexFlat for direct access
    faiss::IndexFlat* flat_index = dynamic_cast<faiss::IndexFlat*>(index);

    if (flat_index) {
        // Direct access to the underlying storage
        const float* data = flat_index->get_xb();

        for (int i = 0; i < n; ++i) {
            std::vector<float> vec(data + i * d, data + (i + 1) * d);
            embeddings.push_back(vec);
        }
    } else {
        // For other index types, use reconstruct method
        for (int i = 0; i < n; ++i) {
            std::vector<float> vec(d);
            index->reconstruct(i, vec.data());
            embeddings.push_back(vec);
        }
    }

    return embeddings;
}
