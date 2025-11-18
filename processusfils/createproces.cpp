#include <windows.h>
#include <iostream>

int main() {
    std::cout << "fils démarré, PID: " << GetCurrentProcessId() << std::endl;

    // Simule un travail
    Sleep(10000); 
    return 0;
}
