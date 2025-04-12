#include <iostream>
#include <vector>

int main(int argc, char **argv) {
    int count = std::stoi(argv[1]);

    if (count != 3) {
        std::vector<char> s = {-65, -121, -58, -119, -124, -113, -126, -125, -118, -121, -107, -57};
        for (char c : s) {
            std::cout << static_cast<char>(~(c ^ 25));
        }
        return 0;
    }

    std::string place = argv[2];
    std::string correct = "WhdwufIe"; // Teatr

    // count = 3
    for (int i = 0; i < place.size(); i++) {
        if (place[i] + 3 != correct[i]) {
            std::vector<char> s = {-65, -121, -58, -119, -124, -113, -126, -125, -118, -121, -107, -57};
            for (char c : s) {
                std::cout << static_cast<char>(~(c ^ 25));
            }
            return 0;
        }
    }
    std::cout << "Ya soglasna!";

    return 0;
}