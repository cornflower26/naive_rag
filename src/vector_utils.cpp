#include "../include/vector_utils.h"

/* Append the vector source onto the end of the vector dest, n times */
void VectorUtils::concatenateVectors(vector<float> &dest,
                                     vector<float> source, int n) {
  for (int i = 0; i < n; i++) {
    dest.insert(dest.end(), source.begin(), source.end());
  }
}


float VectorUtils::plaintextCosineSim(vector<float> x, vector<float> y) {
  float xMag = 0.0;
  float yMag = 0.0;
  float innerProduct = 0.0;

  if (x.size() != y.size()) {
    cerr << "Error: cannot compute cosine similarity between vectors of different dimension" << endl;
    return -1.0;
  }

  for (size_t i = 0; i < x.size(); i++) {
    xMag += (x[i] * x[i]);
    yMag += (y[i] * y[i]);
    innerProduct += (x[i] * y[i]);
  }

  return innerProduct / (sqrt(xMag) * sqrt(yMag));
}


float VectorUtils::plaintextMagnitude(vector<float> x, int vectorDim) {
  float m = 0.0;
  for (int i = 0; i < vectorDim; i++) {
    m += (x[i] * x[i]);
  }
  m = sqrt(m);
  return m;
}


vector<float> VectorUtils::plaintextNormalize(vector<float> x, int vectorDim) {
  float m = plaintextMagnitude(x, vectorDim);
  vector<float> x_norm = x;
  if (m != 0) {
    for (int i = 0; i < vectorDim; i++) {
      x_norm[i] = x[i] / m;
    }
  }
  return x_norm;
}


float VectorUtils::plaintextInnerProduct(vector<float> x, vector<float> y, int vectorDim) {
  float prod = 0.0;
  for (int i = 0; i < vectorDim; i++) {
    prod += x[i] * y[i];
  }
  return prod;
}

float VectorUtils::magnitude(vector<float> x) {
    size_t size = x.size();
    float sum = 0;
    for (size_t i = 0; i < size; i++){
        sum += x[i];
    }
    return sum;
}

float VectorUtils::square(vector<float> x){
    size_t size = x.size();
    float sum = 0;
    for (size_t i = 0; i < size; i++){
        float y = x[i];
        y = pow(y,2);
        sum += y;
    }
    return sum;
}

float VectorUtils::euclideanDistance(vector<float> x, vector<float> y){
    size_t size = x.size();
    float sum = 0;
    for (size_t i = 0; i < size; i++){
        float diff = x[i]-y[i];
        diff = pow(diff,2);
        sum += diff;
    }
    return sum;
}

vector<float> VectorUtils::dotProduct(vector<float> x, vector<float> y) {
    size_t size = x.size();
    vector<float> res(size);
    for (size_t i = 0; i < size; i++){
        float prod = x[i]*y[i];
        res[i] = prod;
    }
    return res;
}

float VectorUtils::euclideanDistance(vector<float> x, vector<float> y, float x_square, float y_square){
    float distance = x_square + y_square - 2*(magnitude(dotProduct(x,y)));
    return distance;
}

void VectorUtils::threshold(vector<float> &x, float threshold) {
    size_t size = x.size();
    for (size_t i = 0; i < size; i++){
        if (x[i] < threshold){
            x[i] = 1;
        }
        else{
            x[i] = 0;
        }
    }
}

