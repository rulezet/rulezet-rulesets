rule TTP_XOR_QUAD_CurrentVersionRun_31db {
  strings:
    $key_31db = { 62 b4 [2] 46 ba [2] 6d 96 [2] 43 b4 [2] 57 af [2] 58 b5 [2] 46 a8 [2] 44 a9 [2] 5f af [2] 43 a8 [2] 5f 87 }

  condition:
    any of them
}