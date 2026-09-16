rule TTP_XOR_QUAD_CurrentVersionRun_5ec5 {
  strings:
    $key_5ec5 = { 0d aa [2] 29 a4 [2] 02 88 [2] 2c aa [2] 38 b1 [2] 37 ab [2] 29 b6 [2] 2b b7 [2] 30 b1 [2] 2c b6 [2] 30 99 }

  condition:
    any of them
}