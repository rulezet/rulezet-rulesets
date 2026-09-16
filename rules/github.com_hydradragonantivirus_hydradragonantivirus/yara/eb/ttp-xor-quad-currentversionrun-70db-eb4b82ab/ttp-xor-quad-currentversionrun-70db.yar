rule TTP_XOR_QUAD_CurrentVersionRun_70db {
  strings:
    $key_70db = { 23 b4 [2] 07 ba [2] 2c 96 [2] 02 b4 [2] 16 af [2] 19 b5 [2] 07 a8 [2] 05 a9 [2] 1e af [2] 02 a8 [2] 1e 87 }

  condition:
    any of them
}