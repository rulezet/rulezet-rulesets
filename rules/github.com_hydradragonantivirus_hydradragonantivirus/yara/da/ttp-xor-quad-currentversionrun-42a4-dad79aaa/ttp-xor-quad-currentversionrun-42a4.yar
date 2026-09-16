rule TTP_XOR_QUAD_CurrentVersionRun_42a4 {
  strings:
    $key_42a4 = { 11 cb [2] 35 c5 [2] 1e e9 [2] 30 cb [2] 24 d0 [2] 2b ca [2] 35 d7 [2] 37 d6 [2] 2c d0 [2] 30 d7 [2] 2c f8 }

  condition:
    any of them
}