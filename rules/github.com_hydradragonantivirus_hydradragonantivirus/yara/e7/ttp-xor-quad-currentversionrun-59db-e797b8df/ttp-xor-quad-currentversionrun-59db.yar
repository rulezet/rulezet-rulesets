rule TTP_XOR_QUAD_CurrentVersionRun_59db {
  strings:
    $key_59db = { 0a b4 [2] 2e ba [2] 05 96 [2] 2b b4 [2] 3f af [2] 30 b5 [2] 2e a8 [2] 2c a9 [2] 37 af [2] 2b a8 [2] 37 87 }

  condition:
    any of them
}