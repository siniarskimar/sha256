/* SPDX-License-Identifier: Unlicense
 */
#ifndef SHA256_H
#define SHA256_H

#include <array>
#include <cstdint>
#include <cstdio>
#include <ostream>
#include <string_view>
#include <vector>

struct sha256_hash {
  std::array<uint8_t, 32> hash;

  std::string toHex() const noexcept;
  friend std::ostream &operator<<(std::ostream &ss, const sha256_hash &h);
};

sha256_hash sha256_digest(const std::vector<uint8_t> &src);
sha256_hash sha256_digest(const std::string_view src);
sha256_hash sha256_digest(const uint8_t *data, size_t l);
sha256_hash sha256_digest(std::istream &stream);
sha256_hash sha256_digest(std::FILE *stream);
#endif