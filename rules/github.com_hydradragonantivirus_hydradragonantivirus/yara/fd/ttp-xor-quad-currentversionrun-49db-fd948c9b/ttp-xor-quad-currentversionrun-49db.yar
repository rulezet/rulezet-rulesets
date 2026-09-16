rule TTP_XOR_QUAD_CurrentVersionRun_49db {
  strings:
    $key_49db = { 1a b4 [2] 3e ba [2] 15 96 [2] 3b b4 [2] 2f af [2] 20 b5 [2] 3e a8 [2] 3c a9 [2] 27 af [2] 3b a8 [2] 27 87 }

  condition:
    any of them
}