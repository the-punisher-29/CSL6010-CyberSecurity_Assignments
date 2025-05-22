#include <iostream>
#include <string>
#include <regex>
#include <cstdlib>
#include <ctime>
#include <unordered_set>
#include <curl/curl.h>

using namespace std;
// Function to check password complexity
string checkPasswordStrength(const string& password) {
    int score = 0;
    // Check for minimum length
    if (password.length() >= 8) score++;
    // Check for uppercase and lowercase letters
    if (regex_search(password, regex("[A-Z]")) && regex_search(password, regex("[a-z]"))) score++;
    // Check for numeric digits
    if (regex_search(password, regex("[0-9]"))) score++;
    // Check for special characters
    if (regex_search(password, regex("[!@#$%^&*(),.?\":{}|<>]"))) score++;
    // Common passwords list
    unordered_set<string> commonPasswords = {"password123", "123456", "12345678", "qwerty", "abc123"};
    if (commonPasswords.find(password) != commonPasswords.end()) {
        return "Weak";
    }
    // Determining strength
    if (score <= 2) return "Weak";
    else if (score == 3) return "Moderate";
    else return "Strong";
}

// Function to generate a 6-digit OTP
string generateOTP() {
    srand(time(0));
    string otp = "";
    for(int i = 0; i < 6; ++i){
        otp += to_string(rand() % 10);
    }
    return otp;
}

// Callback function for libcurl (required but not used in this example)
size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp) {
    string *payload = reinterpret_cast<string*>(userp);
    size_t buffer_size = size * nmemb;
    if(payload->empty()) return 0;
    size_t copy_size = min(payload->size(), buffer_size);
    memcpy(ptr, payload->c_str(), copy_size);
    payload->erase(0, copy_size);
    return copy_size;
}

// Function to send email via Gmail SMTP
// bool sendEmail(const string& to, const string& otp) {
//     CURL *curl;
//     CURLcode res = CURLE_OK;
//     struct curl_slist *recipients = NULL;
//     string from = "your_email@gmail.com";
//     string subject = "Subject: Your OTP Code\r\n";
//     string body = "Your OTP is: " + otp + "\r\n";
//     string payload = subject + "\r\n" + body;

//     curl = curl_easy_init();
//     if(curl){
//         // Set SMTP server and port
//         curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");
//         // Enable TLS
//         curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
//         // Set username and password
//         curl_easy_setopt(curl, CURLOPT_USERNAME, "your_email@gmail.com");
//         curl_easy_setopt(curl, CURLOPT_PASSWORD, "your_app_password");
//         // Set mail from
//         curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "<your_email@gmail.com>");
//         // Add recipient
//         recipients = curl_slist_append(recipients, to.c_str());
//         curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
//         // Set payload
//         curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
//         curl_easy_setopt(curl, CURLOPT_READDATA, &payload);
//         curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
//         // Perform the send
//         res = curl_easy_perform(curl);
//         // Cleanup
//         curl_slist_free_all(recipients);
//         curl_easy_cleanup(curl);
//     }

//     return (res == CURLE_OK);
// }

int main() {
    string password;
    // Prompt user to enter password
    cout << "Enter your password: ";
    cin >> password;

    // Evaluate password strength
    string strength = checkPasswordStrength(password);
    cout << "Password Strength: " << strength << endl;

    if(strength == "Weak"){
        cout << "Please choose a stronger password." << endl;
        return 0;
    }

    string email;
    // Prompt user to enter email
    cout << "Enter your email address: ";
    cin >> email;

    // // Generate OTP
    // string otp = generateOTP();

    // // Send OTP via email
    // if(sendEmail(email, otp)){
    //     cout << "An OTP has been sent to your email address." << endl;
    // }
    // else{
    //     cout << "Failed to send OTP." << endl;
    //     return 0;
    // }

    // // Prompt user to enter OTP
    // string userOTP;
    // cout << "Enter the OTP: ";
    // cin >> userOTP;

    // // Verify OTP
    // if(userOTP == otp){
    //     cout << "OTP Verification: Success" << endl;
    // }
    // else{
    //     cout << "OTP Verification: Failure" << endl;
    // }

    return 0;
}