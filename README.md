# Password Manager

## Overview

This is a **Password Manager** application developed in C++ that allows users to securely store, manage, and retrieve their passwords. The application includes functionality to generate secure random passwords, store them in an encrypted file, and authenticate users with a master password. The program utilizes **AES encryption** for storing passwords securely.

## Features

- **Master Password Authentication**: Secure authentication system using a master password to access the password manager.
- **Password Generation**: Random password generation that ensures strong and secure passwords with uppercase, lowercase letters, digits, and special characters.
- **Password Storage**: Passwords are stored securely with AES encryption, ensuring they are not saved as plain text.
- **Password Retrieval**: Users can retrieve their stored passwords by username.
- **Password Deletion**: Allows users to delete passwords from both the in-memory array and the stored file.
- **Cross-Platform**: The program is developed to work on Linux, macOS, and Windows.

## Requirements

- C++ compiler (GCC, Clang, or MSVC)
- OpenSSL libraries (for AES encryption)
- C++11 or later

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/rockykundu/password-manager-using-C-.git
   
   cd password-manager
Install OpenSSL:

On Linux:

sudo apt-get install libssl-dev
On macOS:

brew install openssl

On Windows: You may need to download and install OpenSSL manually from here.


## Compile the code: Use the following command to compile the code:

g++ -o pass_manager pass_manager.cpp -lssl -lcrypto

Ensure that OpenSSL is correctly linked.

## Usage:
Running the Program
Once compiled, you can run the program with the following command:

./pass_manager


## Menu Options:
Upon running the program, you will see a menu with the following options:

Authenticate: Enter the master password to access the password manager.

Add Password: Add a new password entry.

Get Password: Retrieve a stored password by entering the username.

Delete Password: Remove a password entry by username.

Generate Random Password: Generate a secure random password of a specified length.

Save Passwords: Save all passwords to the encrypted file.

Load Passwords: Load passwords from the encrypted file.

Display All Passwords: Show all stored passwords (encrypted).

Exit: Exit the program.
