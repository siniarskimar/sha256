#include <fstream>
#include <iostream>
#include <string_view>

#include "./sha256.hpp"

int main(int argc, const char *argv[]) {
  if (argc >= 2 && std::string_view(argv[1]) != "-") {
    // std::ifstream stream(argv[1], std::ios_base::in | std::ios_base::binary);

    // if (!stream.is_open()) {
    //   std::cerr << "'" << argv[1] << "' could not be opened" << std::endl;
    //   return 1;
    // }
    auto stream = fopen(argv[1], "rb");
    if (stream == nullptr) {
      std::cerr << "'" << argv[1] << "' could not be opened" << std::endl;
      return 1;
    }
    setvbuf(stream, nullptr, _IOFBF, 64 * 1024);

    std::cout << sha256_digest(stream) << std::endl;
    fclose(stream);
  } else {
    std::ios::sync_with_stdio(false);
    std::cout << sha256_digest(std::cin) << std::endl;
  }
  return 0;
}
