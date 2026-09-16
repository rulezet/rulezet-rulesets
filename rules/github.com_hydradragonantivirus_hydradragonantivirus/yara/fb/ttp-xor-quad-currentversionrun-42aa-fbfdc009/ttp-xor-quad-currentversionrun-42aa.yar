rule TTP_XOR_QUAD_CurrentVersionRun_42aa {
  strings:
    $key_42aa = { 11 c5 [2] 35 cb [2] 1e e7 [2] 30 c5 [2] 24 de [2] 2b c4 [2] 35 d9 [2] 37 d8 [2] 2c de [2] 30 d9 [2] 2c f6 }

  condition:
    any of them
}