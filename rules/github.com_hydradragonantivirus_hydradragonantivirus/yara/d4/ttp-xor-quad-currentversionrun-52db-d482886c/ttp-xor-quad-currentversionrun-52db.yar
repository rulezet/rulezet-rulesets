rule TTP_XOR_QUAD_CurrentVersionRun_52db {
  strings:
    $key_52db = { 01 b4 [2] 25 ba [2] 0e 96 [2] 20 b4 [2] 34 af [2] 3b b5 [2] 25 a8 [2] 27 a9 [2] 3c af [2] 20 a8 [2] 3c 87 }

  condition:
    any of them
}