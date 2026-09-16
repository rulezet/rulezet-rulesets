rule TTP_XOR_QUAD_CurrentVersionRun_66db {
  strings:
    $key_66db = { 35 b4 [2] 11 ba [2] 3a 96 [2] 14 b4 [2] 00 af [2] 0f b5 [2] 11 a8 [2] 13 a9 [2] 08 af [2] 14 a8 [2] 08 87 }

  condition:
    any of them
}