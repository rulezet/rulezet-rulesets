rule TTP_XOR_QUAD_CurrentVersionRun_5ec7 {
  strings:
    $key_5ec7 = { 0d a8 [2] 29 a6 [2] 02 8a [2] 2c a8 [2] 38 b3 [2] 37 a9 [2] 29 b4 [2] 2b b5 [2] 30 b3 [2] 2c b4 [2] 30 9b }

  condition:
    any of them
}