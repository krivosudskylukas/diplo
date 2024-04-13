#include <ctime>
#include "../headers/create_file.h"

using namespace std;
using json = nlohmann::json;


json createJsonBase(string name, time_t startDate, time_t expirationDate ,vector<string> functionality) {
    json jsonFile;

    if (difftime(expirationDate, startDate) < 0) {
        throw invalid_argument("Start date must be lower than expiration date.");
    }
    
    jsonFile["Name"] = name;
    jsonFile["Starting_Date"] = startDate;
    jsonFile["Expiration_Date"] = expirationDate;
    jsonFile["Functionality"] = functionality;
    
    return jsonFile;
}


void createJsonFile(string name, time_t startDate, time_t expirationDate, vector<string> functionality) {
    json j = createJsonBase(name, startDate, expirationDate, functionality);
    string jsonDump = j.dump();

    ofstream jsonFile;
    jsonFile.open("licenseFile.json");
    jsonFile << jsonDump;
    jsonFile.close();
}

time_t createExpirationDate() {
    
    // Get current time as time_t
    time_t currentTime = time(nullptr);
    
    // Convert to local time
    struct tm* now = localtime(&currentTime);

    // Prepare for next month: set day to 1 and increment month
    struct tm expDate = {0};
    expDate.tm_mday = 1; // Always the first day of the month
    expDate.tm_mon = now->tm_mon + 1; // Increment month
    expDate.tm_year = now->tm_year;

    // Handle December to January transition
    if (expDate.tm_mon > 11) { // tm_mon is 0-based, December is 11
        expDate.tm_mon = 0; // Set to January
        expDate.tm_year += 1; // Increment the year
    }

    // mktime adjusts the tm structure and returns the correct timestamp
    return mktime(&expDate);
    
    
    /*struct tm expDate = {0};
    expDate.tm_year = year - 1900;
    expDate.tm_mon = month - 1;
    expDate.tm_mday = day;
    return mktime(&expDate);*/
}

json loadJsonFile(string name) {
    ifstream i(name);
    json file = json::parse(i);
    cout << file["Name"] << "\n";
    cout << file["Starting_Date"] << "\n";
    cout << file["Functionality"][0];
    return file;
}



/*int main() {

    string name = "Test";
    time_t startDate = time(0);
    time_t expirationDate = createExpirationDate(19,2,2021);
    vector<string> functionality{ "Scan","Xray","Messages" };
    
    json j = loadJsonFile("licenseFile.json");

    try {
        createJsonFile(name, startDate, expirationDate, functionality);
    }
    catch(const invalid_argument &e){
        cout << e.what();
    }
    
    return 0;
}*/