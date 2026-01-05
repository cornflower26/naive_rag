// ** Contains the functionalities for loading and processing of plaintext data vectors.

#ifndef VECTOR_UTIL_H
#define VECTOR_UTIL_H

#pragma once

#include <cstddef>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>

using namespace std;

namespace VectorUtils {

void concatenateVectors(vector<float> &dest, vector<float> source,
                        int n);

float plaintextCosineSim(vector<float> x, vector<float> y);

float plaintextMagnitude(vector<float> x, int vectorDim);

vector<float> plaintextNormalize(vector<float> x, int vectorDim);

float plaintextInnerProduct(vector<float> x, vector<float> y, int vectorDim);

float square(vector<float> x);

float euclideanDistance(vector<float> x, vector<float> y);

float euclideanDistance(vector<float> x, vector<float> y, float x_square, float y_square);

vector<float> dotProduct(vector<float> x, vector<float> y);

float magnitude(vector<float> x);

void threshold(vector<float> &x, float threshold);
} // namespace VectorUtils

#endif