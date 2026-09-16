rule TTP_XOR_QUAD_CurrentVersionRun_47db {
  strings:
    $key_47db = { 14 b4 [2] 30 ba [2] 1b 96 [2] 35 b4 [2] 21 af [2] 2e b5 [2] 30 a8 [2] 32 a9 [2] 29 af [2] 35 a8 [2] 29 87 }

  condition:
    any of them
}