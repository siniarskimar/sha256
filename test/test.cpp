#include "sha256.hpp"
#include <catch2/catch_all.hpp>

TEST_CASE("hello string") {
  REQUIRE(sha256_digest("hello").toHex() ==
          "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  REQUIRE(sha256_digest("hello\n").toHex() ==
          "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03");
}

TEST_CASE("binary blob") {
  REQUIRE(
      sha256_digest(
          "QpjqNX!uba79L99AFH2ObJXvRTYqma~9PDRBCWsvdngzF!Y8&Wn_mtEGk5oUk&cjroR)"
          "TykF8bOD^L&*ZNCvGizKUyxHoj1znmA8@8Jzh!up2y3qhoc))YbXQq~"
          "UmS4SZMoxZRdRbItap0I4ix8I3jtW6xYBq1#LtAhZn!")
          .toHex() ==
      "569e4489da6a1186babfa1f1287d31aa9763ebceadb40f98e1ef8c9e6056d8c3");
}
