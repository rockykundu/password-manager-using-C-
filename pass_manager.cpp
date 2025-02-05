#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <openssl/evp.h>  // Include OpenSSL EVP for AES encryption

using namespace std;

class PasswordManager {
private:
    string masterPassword;
    struct UserPassword {
        string username;
        string password;
    };
    UserPassword storedPasswords[100];
    int numPasswords;

    // Encryption/decryption key (for simplicity, using a static key here; it should be kept secure)
    static const unsigned char encryptionKey[16];  // AES 128-bit key (16 bytes)
    static const unsigned char iv[16];  // AES 128-bit Initialization Vector

public:
    PasswordManager() : numPasswords(0) {}

    // Method to set the master password
    void setMasterPassword(string password) {
        masterPassword = password;
    }

    // Method to authenticate the user with the master password
    bool authenticate(string password) {
        return password == masterPassword;
    }

    // Method to generate a secure random password
    string generateRandomPassword(int length) {
        const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=<>?";
        string password = "";
        srand(time(0));

        for (int i = 0; i < length; i++) {
            password += characters[rand() % characters.length()];
        }

        return password;
    }

    // Encrypt a string using AES with EVP
    string encryptPassword(const string& password) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        unsigned char encryptedPassword[128];  // Assuming the encrypted password won't exceed 128 bytes
        int len;
        int ciphertext_len;

        // Initialize the encryption context with AES-128-CBC mode
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, encryptionKey, iv);
        EVP_EncryptUpdate(ctx, encryptedPassword, &len, reinterpret_cast<const unsigned char*>(password.c_str()), password.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, encryptedPassword + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        // Convert the encrypted password to a hex string for easy storage
        string encryptedHex = "";
        for (int i = 0; i < ciphertext_len; i++) {
            encryptedHex += hexify(encryptedPassword[i]);
        }

        return encryptedHex;
    }

    // Decrypt an encrypted string using AES with EVP 
    string decryptPassword(const string& encryptedPassword) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        unsigned char decryptedPassword[128];
        int len;
        int decryptedTextLen;

        // Convert hex string back to bytes
        unsigned char encryptedBytes[128];
        for (int i = 0; i < encryptedPassword.length() / 2; i++) {
            encryptedBytes[i] = unhexify(encryptedPassword.substr(i * 2, 2));
        }

        // Initialize the decryption context with AES-128-CBC mode
        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, encryptionKey, iv);
        EVP_DecryptUpdate(ctx, decryptedPassword, &len, encryptedBytes, encryptedPassword.length() / 2);
        decryptedTextLen = len;
        EVP_DecryptFinal_ex(ctx, decryptedPassword + len, &len);
        decryptedTextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        return string(reinterpret_cast<char*>(decryptedPassword), decryptedTextLen);
    }

    // Add password and store encrypted password
    void addPassword(string username, string password) {
        if (numPasswords < 100) {
            storedPasswords[numPasswords].username = username;
            storedPasswords[numPasswords].password = encryptPassword(password); // Encrypt password
            numPasswords++;
        }
    }

    // Retrieve and decrypt password
    string getPassword(string username) {
        for (int i = 0; i < numPasswords; i++) {
            if (storedPasswords[i].username == username) {
                return decryptPassword(storedPasswords[i].password); // Decrypt password
            }
        }
        return "Password not found.";
    }

    // Save encrypted passwords to file
    void savePasswordsToFile(string filename) {
        ofstream outFile(filename, ios::binary);
        if (!outFile) {
            cout << "Error opening file for writing." << endl;
            return;
        }

        for (int i = 0; i < numPasswords; i++) {
            outFile << storedPasswords[i].username << "\n" << storedPasswords[i].password << "\n";
        }

        outFile.close();
    }

    // Delete a password entry by username
    void deletePassword(string username) {
        bool found = false;

        // Find the index of the password to delete
        for (int i = 0; i < numPasswords; i++) {
            if (storedPasswords[i].username == username) {
                // Shift passwords down by one position
                for (int j = i; j < numPasswords - 1; j++) {
                    storedPasswords[j] = storedPasswords[j + 1]; // Shift passwords left
                }
                numPasswords--;  // Decrease the number of stored passwords
                cout << "Password for username " << username << " deleted successfully." << endl;
                found = true;
                break;
            }
        }
        if (!found) {
            cout << "Username not found." << endl;
        }
    }
    
    // Load encrypted passwords from file
    void loadPasswordsFromFile(string filename) {
        ifstream inFile(filename);
        if (!inFile) {
            cout << "Error opening file for reading." << endl;
            return;
        }

        string username, encryptedPassword;
        while (getline(inFile, username) && getline(inFile, encryptedPassword)) {
            addPassword(username, encryptedPassword); // Store encrypted password
        }

        inFile.close();
    }

    // Display all passwords (encrypted form)
    void displayAllPasswords() {
        for (int i = 0; i < numPasswords; i++) {
            cout << "Username: " << storedPasswords[i].username << ", Encrypted Password: " << storedPasswords[i].password << endl;
        }
    }

    // Helper method to convert a byte to hex string
    string hexify(unsigned char byte) {
        const char* hex = "0123456789ABCDEF";
        return string(1, hex[byte >> 4]) + string(1, hex[byte & 0x0F]);
    }

    // Helper method to convert hex string back to byte
    unsigned char unhexify(string hex) {
        unsigned char byte = 0;
        for (int i = 0; i < 2; i++) {
            byte = (byte << 4) | (hex[i] > '9' ? (hex[i] - 'A' + 10) : (hex[i] - '0'));
        }
        return byte;
    }
};

// Static encryption key (128-bit AES key)
const unsigned char PasswordManager::encryptionKey[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x75, 0x46, 0x3b, 0x37, 0x68
};

// Static initialization vector (16 bytes for AES)
const unsigned char PasswordManager::iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};


// Main function to provide user interface
int main() {
    PasswordManager manager;
    string username, password, masterPassword;
    int choice, passwordLength;

    // Setting up master password
    cout << "Set your master password: ";
    cin >> masterPassword;
    manager.setMasterPassword(masterPassword);

    do {
        cout << "\nPassword Manager Menu\n";
        cout << "1. Authenticate\n";
        cout << "2. Add Password\n";
        cout << "3. Get Password\n";
        cout << "4. Delete Password\n";
        cout << "5. Generate Random Password\n";
        cout << "6. Save Passwords\n";
        cout << "7. Load Passwords\n";
        cout << "8. Display All Passwords\n";
        cout << "9. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
            case 1:
                // Authenticate user
                cout << "Enter master password: ";
                cin >> password;
                if (manager.authenticate(password)) {
                    cout << "Authenticated successfully!" << endl;
                } else {
                    cout << "Incorrect master password!" << endl;
                }
                break;

            case 2:
                // Add password
                cout << "Enter username: ";
                cin >> username;
                cout << "Enter password: ";
                cin >> password;
                manager.addPassword(username, password);
                cout << "Password added successfully!" << endl;
                break;

            case 3:
                // Retrieve password
                cout << "Enter username: ";
                cin >> username;
                cout << "Password: " << manager.getPassword(username) << endl;
                break;

            case 4:
                // Delete password
                cout << "Enter username to delete: ";
                cin >> username;
                manager.deletePassword(username);
                break;

            case 5:
                // Generate random password
                cout << "Enter password length: ";
                cin >> passwordLength;
                cout << "Generated Password: " << manager.generateRandomPassword(passwordLength) << endl;
                break;

            case 6:
                // Save passwords to file
                manager.savePasswordsToFile("passwords.dat");
                cout << "Passwords saved successfully." << endl;
                break;

            case 7:
                // Load passwords from file
                manager.loadPasswordsFromFile("passwords.dat");
                cout << "Passwords loaded successfully." << endl;
                break;

            case 8:
                // Display all stored passwords
                manager.displayAllPasswords();
                break;

            case 9:
                // Exit the program
                cout << "Exiting Password Manager." << endl;
                break;

            default:
                cout << "Invalid choice! Please try again." << endl;
        }
    } while (choice != 9);

    return 0;
}





