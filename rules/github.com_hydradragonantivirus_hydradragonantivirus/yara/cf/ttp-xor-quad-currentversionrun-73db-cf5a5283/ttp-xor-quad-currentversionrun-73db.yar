rule TTP_XOR_QUAD_CurrentVersionRun_73db {
  strings:
    $key_73db = { 20 b4 [2] 04 ba [2] 2f 96 [2] 01 b4 [2] 15 af [2] 1a b5 [2] 04 a8 [2] 06 a9 [2] 1d af [2] 01 a8 [2] 1d 87 }

  condition:
    any of them
}