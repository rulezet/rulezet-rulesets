rule TTP_XOR_QUAD_CurrentVersionRun_69db {
  strings:
    $key_69db = { 3a b4 [2] 1e ba [2] 35 96 [2] 1b b4 [2] 0f af [2] 00 b5 [2] 1e a8 [2] 1c a9 [2] 07 af [2] 1b a8 [2] 07 87 }

  condition:
    any of them
}