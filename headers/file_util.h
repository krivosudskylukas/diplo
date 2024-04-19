#ifndef FILE_UTIL_H
#define FILE_UTIL_H
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
void writeStringFile(string name, string content);

#endif // FILE_UTIL_H
