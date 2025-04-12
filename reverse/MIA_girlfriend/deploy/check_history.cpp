#include <iostream>
#include <vector>
#include <cstdint>

// Never_gonna_give_you_up

uint64_t customCharHash(char c) {
    return (c * 271 + 52) % 255; // Пример простой хэш-функции
}

int main(int argc, char **argv) {
    std::string compliment = argv[2];
    int count = std::stoi(argv[1]);

    std::vector<uint64_t> data = {26, 139, 156, 139, 92, 43, 171, 44, 28, 28, 75, 43, 171, 203, 156, 139, 43, 204, 44,
                                  140, 43, 140, 60};

    for (int i = 0; i < 23; ++i) {
        uint64_t cur = customCharHash(compliment[i]) + count;
//        std::cout << cur << ", ";
        if (cur != data[i]) {
            std::cout << "Chto-to ty ne umeesh rasskazyvat istorii. Ya obidelas!" << std::endl;
            return 1;
        }
    }
    std::cout << "Interesno!" << std::endl;

    return 0;
}