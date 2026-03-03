#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <oqs/oqs.h>
#pragma comment(lib, "ws2_32.lib")

int main() {
    // Check OpenSSL
    SSL_library_init();
    std::cout << "OpenSSL initialized" << std::endl;

    // Check liboqs
    std::cout << "liboqs version: " 
              << OQS_version() << std::endl;

    return 0;
}