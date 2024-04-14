#include <ctime>
#include "../headers/file_util.h"

using namespace std;
using json = nlohmann::json;


json createJsonBase(string name, time_t startDate, time_t expirationDate ,vector<string> functionality) {
    json jsonFile;

    if (difftime(expirationDate, startDate) < 0) {
        throw invalid_argument("Start date must be lower than expiration date.");
    }
    
    return json{
        {"Name", name},
        {"Starting_Date", startDate},
        {"Expiration_Date", expirationDate},
        {"Functionality", functionality}
    };
}


void createJsonFile(string name, time_t startDate, time_t expirationDate, vector<string> functionality) {
    const json json = createJsonBase(name, startDate, expirationDate, functionality);
    const string jsonDump = json.dump();
    const string fileName = "licenseFile.json";


    if(!filesystem::exists(fileName)){
        ofstream outFile(fileName);
        if (!outFile) {
            throw runtime_error("Failed to create file: " + fileName);
        }
        outFile.close();
    }

    // Open the file in append mode
    ofstream jsonFile(fileName, ios_base::out);
    if (!jsonFile) {
        throw runtime_error("Failed to open file: " + fileName);
    }
    jsonFile << jsonDump;
    jsonFile.close();
}

time_t createExpirationDate() {
    
    // Get current time as time_t
    time_t currentTime = time(nullptr);
    
    // Convert to local time
    struct tm* expirationDate = localtime(&currentTime);

    expirationDate->tm_mday = 4; // Always the fourth day of the month
    expirationDate->tm_mon += 1; // Increment month
    expirationDate->tm_hour = 0; // Set hours to 00
    expirationDate->tm_min = 0;  // Set minutes to 00
    expirationDate->tm_sec = 0;  // Set seconds to 00


    // Handle December to January transition
    if (expirationDate->tm_mon > 11) { // tm_mon is 0-based, December is 11
        expirationDate->tm_mon = 0; // Set to January
        expirationDate->tm_year += 1; // Increment the year
    }

    // mktime adjusts the tm structure and returns the correct timestamp
    return mktime(expirationDate);
}

time_t createStartingDate(){
    time_t currentTime = time(nullptr);
    struct tm* startingStade = localtime(&currentTime);

    startingStade->tm_mday = 1; // Always the first day of the month
    startingStade->tm_hour = 0; // Set hours to 00
    startingStade->tm_min = 0;  // Set minutes to 00
    startingStade->tm_sec = 0;  // Set seconds to 00

    return mktime(startingStade);
}

json loadJsonFile(string name) {
    ifstream jsonFile(name);
    if (!jsonFile.is_open()) {
        throw runtime_error("Failed to open file: " + name);
    }

    json data;
    try {
        jsonFile >> data;
    } catch (const json::parse_error& e) {
        throw runtime_error("Failed to parse JSON: " + string(e.what()));
    }

    return data;
}



/*int main() {

    string name = "Kramare";
    time_t startDate = time(0);
    time_t expirationDate = createExpirationDate();
    fprintf(stdout, "Expiration Date: %s", ctime(&expirationDate));
    vector<string> functionality{ "Scan","Xray","Messages" };

    time_t startingDate = createStartingDate();

    fprintf(stdout, "Expiration Date: %s", ctime(&startingDate));
    

    try {
        createJsonFile(name, startDate, expirationDate, functionality);
    }
    catch(const invalid_argument &e){
        cout << e.what();
    }
    json j = loadJsonFile("licenseFile.json");

    fprintf(stdout, "Name: %s\n", j["Name"].dump().c_str());
    
    return 0;
}*/