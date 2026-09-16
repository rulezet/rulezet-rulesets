rule TTP_XOR_QUAD_CurrentVersionRun_42c5 {
  strings:
    $key_42c5 = { 11 aa [2] 35 a4 [2] 1e 88 [2] 30 aa [2] 24 b1 [2] 2b ab [2] 35 b6 [2] 37 b7 [2] 2c b1 [2] 30 b6 [2] 2c 99 }

  condition:
    any of them
}