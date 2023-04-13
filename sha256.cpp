/* SPDX-License-Identifier: Unlicense
 */
#include "./sha256.hpp"
#include <boost/endian.hpp>
#include <cstring>
#include <iostream>

static constexpr std::array<uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static constexpr inline uint32_t frotr(const uint32_t x, const uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

static constexpr inline uint32_t fsig0(const uint32_t x) {
  return frotr(x, 7) ^ frotr(x, 18) ^ (x >> 3);
}

static constexpr inline uint32_t fsig1(const uint32_t x) {
  return frotr(x, 17) ^ frotr(x, 19) ^ (x >> 10);
}

static constexpr inline uint32_t fSIG0(const uint32_t x) {
  return frotr(x, 2) ^ frotr(x, 13) ^ frotr(x, 22);
}

static constexpr inline uint32_t fSIG1(const uint32_t x) {
  return frotr(x, 6) ^ frotr(x, 11) ^ frotr(x, 25);
}

static constexpr inline uint32_t fchoice(const uint32_t x, const uint32_t y,
                                         const uint32_t z) {
  return ((x) & (y)) ^ (~(x) & (z));
}
static constexpr inline uint32_t fmajority(const uint32_t x, const uint32_t y,
                                           const uint32_t z) {
  return ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z));
}

void sha256_digest_block(const uint8_t *block, uint32_t hash[8]) {
  uint32_t W[64]{};
  uint32_t A = hash[0];
  uint32_t B = hash[1];
  uint32_t C = hash[2];
  uint32_t D = hash[3];
  uint32_t E = hash[4];
  uint32_t F = hash[5];
  uint32_t G = hash[6];
  uint32_t H = hash[7];

  for (uint8_t i = 0; i < 16; i++) {
    W[i] = boost::endian::native_to_big(
        reinterpret_cast<const uint32_t *>(block)[i]);
  }

  for (uint8_t i = 16; i < 64; i++) {
    W[i] = fsig1(W[i - 2]) + W[i - 7] + fsig0(W[i - 15]) + W[i - 16];
  }

  for (uint64_t i = 0; i < 64; i++) {
    uint32_t T1 = H + fSIG1(E) + fchoice(E, F, G) + K[i] + W[i];
    uint32_t T2 = fSIG0(A) + fmajority(A, B, C);

    H = G;
    G = F;
    F = E;
    E = D + T1;
    D = C;
    C = B;
    B = A;
    A = T1 + T2;
  }

  hash[0] += A;
  hash[1] += B;
  hash[2] += C;
  hash[3] += D;
  hash[4] += E;
  hash[5] += F;
  hash[6] += G;
  hash[7] += H;
}

sha256_hash sha256_digest(const uint8_t *data, size_t l) {
  uint32_t hash[8];

  hash[0] = 0x6a09e667;
  hash[1] = 0xbb67ae85;
  hash[2] = 0x3c6ef372;
  hash[3] = 0xa54ff53a;
  hash[4] = 0x510e527f;
  hash[5] = 0x9b05688c;
  hash[6] = 0x1f83d9ab;
  hash[7] = 0x5be0cd19;

  // First hash the blocks that don't need the padding
  // Keep the index to the byte we ended at,
  // it's useful for calculating the padding
  size_t i = 0;
  for (; i < l - (l % 64); i += 64) {
    sha256_digest_block(data + i, hash);
  }

  // `l` is not a multiple of 64
  // we need to pad it (by ceil)
  uint8_t blk[64];

  // `rest` - how many bytes of data left
  int rest = l - i;
  memcpy(blk, data + i, rest);

  blk[rest] = 0x80;
  rest++;
  // if leftover data exceeds 56 bytes, we can't simply pad it. two blocks need
  // to be hashed
  if (rest > 56) {
    // Fill till we hit a boundry of 512 bits
    while (rest < 64) {
      blk[rest] = 0;
      rest++;
    }
    sha256_digest_block(blk, hash);
    rest = 0;
  }

  // Finally pad the last block

  while (rest < 56) {
    blk[rest] = 0;
    rest++;
  }

  *(reinterpret_cast<uint64_t *>(blk + 56)) =
      boost::endian::native_to_big(static_cast<uint64_t>(l * 8));

  sha256_digest_block(blk, hash);

  sha256_hash result;
  for (uint8_t i = 0; i < 8; i++) {
    uint32_t part = boost::endian::big_to_native(hash[i]);
    result.hash[i * 4] = (part & 0xff);
    result.hash[i * 4 + 1] = (part & 0xff00) >> 8;
    result.hash[i * 4 + 2] = (part & 0xff0000) >> 16;
    result.hash[i * 4 + 3] = (part & 0xff000000) >> 24;
  }
  return result;
}

sha256_hash sha256_digest(std::istream &stream) {
  uint32_t hash[8];

  hash[0] = 0x6a09e667;
  hash[1] = 0xbb67ae85;
  hash[2] = 0x3c6ef372;
  hash[3] = 0xa54ff53a;
  hash[4] = 0x510e527f;
  hash[5] = 0x9b05688c;
  hash[6] = 0x1f83d9ab;
  hash[7] = 0x5be0cd19;
  uint8_t block[64]{};
  uint64_t data_size = 0;
  int last_block_len = 0;

  while (true) {
    stream.read(reinterpret_cast<char *>(block), 64);
    last_block_len = stream.gcount();
    data_size += last_block_len;
    if (stream.eof()) {
      memset(block + last_block_len, 0, 64 - last_block_len);
      break;
    }
    sha256_digest_block(block, hash);
  }
  int rest = last_block_len;
  block[last_block_len] = 0x80;
  rest++;

  if (rest > 56) {
    while (rest < 64) {
      block[rest] = 0;
      rest++;
    }
    sha256_digest_block(block, hash);
    rest = 0;
  }

  while (rest < 56) {
    block[rest] = 0;
    rest++;
  }

  *(reinterpret_cast<uint64_t *>(block + 56)) =
      boost::endian::native_to_big(static_cast<uint64_t>(data_size * 8));

  sha256_digest_block(block, hash);

  sha256_hash result;
  for (uint8_t i = 0; i < 8; i++) {
    uint32_t part = boost::endian::big_to_native(hash[i]);
    result.hash[i * 4] = (part & 0xff);
    result.hash[i * 4 + 1] = (part & 0xff00) >> 8;
    result.hash[i * 4 + 2] = (part & 0xff0000) >> 16;
    result.hash[i * 4 + 3] = (part & 0xff000000) >> 24;
  }
  return result;
}

sha256_hash sha256_digest(std::FILE *stream) {
  uint32_t hash[8];

  hash[0] = 0x6a09e667;
  hash[1] = 0xbb67ae85;
  hash[2] = 0x3c6ef372;
  hash[3] = 0xa54ff53a;
  hash[4] = 0x510e527f;
  hash[5] = 0x9b05688c;
  hash[6] = 0x1f83d9ab;
  hash[7] = 0x5be0cd19;
  uint8_t block[64]{};
  uint64_t data_size = 0;
  int last_block_len = 0;

  // TODO: read in bigger chunks
  while (true) {
    last_block_len = fread(block, sizeof(uint8_t), 64, stream);
    data_size += last_block_len;
    if (feof(stream)) {
      memset(block + last_block_len, 0, 64 - last_block_len);
      break;
    }
    sha256_digest_block(block, hash);
  }
  int rest = last_block_len;
  block[last_block_len] = 0x80;
  rest++;

  if (rest > 56) {
    while (rest < 64) {
      block[rest] = 0;
      rest++;
    }
    sha256_digest_block(block, hash);
    rest = 0;
  }

  while (rest < 56) {
    block[rest] = 0;
    rest++;
  }

  *(reinterpret_cast<uint64_t *>(block + 56)) =
      boost::endian::native_to_big(static_cast<uint64_t>(data_size * 8));

  sha256_digest_block(block, hash);

  sha256_hash result;
  for (uint8_t i = 0; i < 8; i++) {
    uint32_t part = boost::endian::big_to_native(hash[i]);
    result.hash[i * 4] = (part & 0xff);
    result.hash[i * 4 + 1] = (part & 0xff00) >> 8;
    result.hash[i * 4 + 2] = (part & 0xff0000) >> 16;
    result.hash[i * 4 + 3] = (part & 0xff000000) >> 24;
  }
  return result;
}
sha256_hash sha256_digest(const std::string_view src) {
  return sha256_digest(reinterpret_cast<const uint8_t *>(src.data()),
                       src.length());
}
sha256_hash sha256_digest(const std::vector<uint8_t> &vec) {
  return sha256_digest(vec.data(), vec.size());
}

std::string sha256_hash::toHex() const noexcept {
  static const char table[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  };
  std::string result;

  for (auto &b : hash) {
    uint8_t h = (b & 0xf0) >> 4;
    uint8_t l = (b & 0xf);
    result += table[h];
    result += table[l];
  }
  return result;
}

std::ostream &operator<<(std::ostream &ss, const sha256_hash &h) {
  ss << h.toHex();
  return ss;
}