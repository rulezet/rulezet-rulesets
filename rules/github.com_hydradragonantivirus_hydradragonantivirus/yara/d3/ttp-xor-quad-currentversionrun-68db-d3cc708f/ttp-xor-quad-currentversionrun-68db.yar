rule TTP_XOR_QUAD_CurrentVersionRun_68db {
  strings:
    $key_68db = { 3b b4 [2] 1f ba [2] 34 96 [2] 1a b4 [2] 0e af [2] 01 b5 [2] 1f a8 [2] 1d a9 [2] 06 af [2] 1a a8 [2] 06 87 }

  condition:
    any of them
}