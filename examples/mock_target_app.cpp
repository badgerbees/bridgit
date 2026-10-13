#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iostream>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif
#include <string>
#include <thread>

static void ensure_output_directory(const std::string& path) {
#ifdef _WIN32
    _mkdir(path.c_str());
#else
    mkdir(path.c_str(), 0755);
#endif
}

int main(int argc, char** argv) {
    int interval = 3;
    std::string output = "examples/output";
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--interval") interval = std::stoi(argv[++i]);
        if (std::string(argv[i]) == "--output") output = argv[++i];
    }
    ensure_output_directory(output);
    std::uint32_t sequence = 1;
    for (;;) {
        const auto id = "RESULT-" + std::to_string(sequence);
        char record_id[16] = {};
        std::memcpy(record_id, id.data(), id.size() < sizeof(record_id) ? id.size() : sizeof(record_id));
        const float value = 20.0f + static_cast<float>(sequence) * 0.25f;
        const std::int16_t status = 0;
        const auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto name = output + "/result_" + std::to_string(timestamp) + "_" +
                          std::to_string(sequence) + ".dat";
        const auto temporary = name + ".tmp";
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        const char magic[2] = {'B', 'R'};
        file.write(magic, sizeof(magic));
        file.write(record_id, sizeof(record_id));
        file.write(reinterpret_cast<const char*>(&value), sizeof(value));
        file.write(reinterpret_cast<const char*>(&status), sizeof(status));
        file.close();
        std::rename(temporary.c_str(), name.c_str());
        std::cout << "wrote " << name << std::endl;
        ++sequence;
        std::this_thread::sleep_for(std::chrono::seconds(interval));
    }
}

