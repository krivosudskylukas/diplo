#ifndef CREATE_FILE_H
#define CREATE_FILE_H
#include <iostream>
#include <fstream>
#include <ctime>
#include <chrono>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <vector>

using json = nlohmann::json;
using namespace std;


json createJsonBase(string name, time_t startDate, time_t expirationDate ,vector<string> functionality);
void createJsonFile(string name, time_t startDate, time_t expirationDate, vector<string> functionality);
time_t createExpirationDate();
time_t createStartingDate();
json loadJsonFile(string name);

#endif // CREATE_FILE_H
