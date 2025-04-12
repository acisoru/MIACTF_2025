#include <iostream>
#include <vector>
#include <cstdint>
#include <fstream>


uint64_t stringHash(const std::string &str) {
    uint64_t hash = 5381; // Начальное значение (магическое число из DJB2)

    for (char c: str) {
        // Обновляем хэш: hash * 33 + c
        hash = ((hash << 5) + hash) + static_cast<uint64_t>(c);
        // Добавляем битовый сдвиг для уменьшения коллизий
        hash ^= (hash >> 15);
    }

    return hash;
}


int f1(const std::string &compliment) {
    if (compliment.size() != 6) {
        std::vector<int> data = {109, 85, 20, 64, 85, 95, 20, 80, 91, 88, 83, 91, 20, 83, 91, 64, 91, 66, 93, 88, 85,
                                 71, 24, 20, 85, 20, 64, 77, 20, 71, 89, 91, 64, 70, 93, 71, 92, 20, 64, 91, 88, 95, 91,
                                 20, 66, 20, 83, 88, 85, 78, 85, 11, 20, 109, 85, 20, 91, 86, 93, 80, 81, 88, 85, 71,
                                 21};

        for (int i: data) {
            std::cout << static_cast<char>(i ^ 52);
        }
        std::cout << std::endl;
        return 0;
    }

    uint64_t hash = stringHash(compliment);
    if (hash != 6952640754009) {
        std::vector<int> data = {109, 85, 20, 64, 85, 95, 20, 80, 91, 88, 83, 91, 20, 66, 77, 86, 93, 70, 85, 88, 85,
                                 20, 68, 88, 85, 64, 77, 81, 24, 20, 85, 20, 64, 77, 20, 90, 81, 20, 91, 87, 81, 90, 93,
                                 88, 21, 20, 109, 85, 20, 91, 86, 93, 80, 81, 88, 85, 71, 21};

        for (int i: data) {
            std::cout << static_cast<char>(i ^ 52);
        }
        std::cout << std::endl;
        return 0;
    }

    std::vector<int> data = {103, 68, 85, 71, 93, 86, 91, 20, 78, 85, 20, 87, 91, 89, 68, 88, 93, 89, 81, 90, 64, 21,
                             20, 121, 90, 81, 20, 68, 70, 93, 77, 85, 64, 90, 91, 29};

    for (int i: data) {
        std::cout << static_cast<char>(i ^ 52);
    }
    std::cout << std::endl;

    return 0;
}


int f2(const std::string &compliment) {
    std::vector<int> data = {96, 77, 20, 87, 92, 64, 91, 24, 20, 65, 89, 81, 81, 71, 92, 20, 64, 91, 88, 95, 91, 20, 80,
                             81, 88, 85, 64, 20, 87, 91, 89, 68, 88, 93, 89, 81, 90, 64, 77, 11, 20, 109, 85, 20, 91,
                             86, 93, 80, 81, 88, 85, 71, 21};

    for (int i: data) {
        std::cout << static_cast<char>(i ^ 52);
    }
    std::cout << std::endl;
    return 0;
}

int f3(const std::string &compliment) {
    // count = 2
    if (compliment.size() != 6) {
        std::vector<char> s = {-65, -121, -58, -119, -124, -113, -126, -125, -118, -121, -107, -57};
        for (char c : s) {
            std::cout << static_cast<char>(~(c ^ 25));
        }
        return 1;
    }

    // Makyaz
    std::vector<char> s = {-33, -9, -11, -27, -22, -29};
    std::vector<char> res;
    std::string s2 = "miactf";

    for (int i = 0; i < s.size(); i++) {
        res.push_back(static_cast<char>(~(s[i] ^ compliment[i])));
    }

    for (int i = 0; i < s2.size(); i++) {
        if (s2[i] != res[i]) {
            std::vector<char> s3 = {-65, -121, -58, -119, -124, -113, -126, -125, -118, -121, -107, -57};
            for (char c : s3) {
                std::cout << static_cast<char>(~(c ^ 25));
            }
            return 1;
        }
    }

    std::vector<int> data = {103, 68, 85, 71, 93, 86, 91, 20, 78, 85, 20, 87, 91, 89, 68, 88, 93, 89, 81, 90, 64, 21,
                             20, 121, 90, 81, 20, 68, 70, 93, 77, 85, 64, 90, 91, 29};

    for (int i: data) {
        std::cout << static_cast<char>(i ^ 52);
    }

    return 0;
}

int f4(const std::string &compliment) {
    std::vector<int> data = {109, 85, 20, 65, 71, 64, 85, 88, 85, 20, 91, 64, 20, 64, 66, 91, 93, 87, 92, 20, 71, 88,
                             91, 66, 21, 20, 124, 91, 87, 92, 65, 20, 80, 81, 77, 71, 64, 66, 93, 77, 21, 20, 109, 85,
                             20, 91, 86, 93, 80, 81, 88, 85, 71, 21};

    for (int i: data) {
        std::cout << static_cast<char>(i ^ 52);
    }
    std::cout << std::endl;

    return 0;
}

int f5(const std::string &compliment) {
    std::vector<int> data = {122, 65, 20, 71, 87, 91, 88, 95, 91, 20, 89, 91, 78, 92, 90, 91, 20, 83, 91, 66, 91, 70,
                             93, 64, 11, 20, 110, 92, 80, 65, 20, 80, 81, 77, 71, 64, 66, 93, 77, 21, 20, 109, 85, 20,
                             91, 86, 93, 80, 81, 88, 85, 71, 21};

    for (int i: data) {
        std::cout << static_cast<char>(i ^ 52);
    }
    std::cout << std::endl;

    return 0;
}

int main(int argc, char **argv) {
    std::string compliment = argv[2];
    int count = std::stoi(argv[1]);

    int (*functions[])(const std::string &) = {f1, f2, f3, f4, f5};
    functions[count](compliment);

    return 0;
}
