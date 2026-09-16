rule TTP_XOR_QUAD_CurrentVersionRun_73b7 {
  strings:
    $key_73b7 = { 20 d8 [2] 04 d6 [2] 2f fa [2] 01 d8 [2] 15 c3 [2] 1a d9 [2] 04 c4 [2] 06 c5 [2] 1d c3 [2] 01 c4 [2] 1d eb }

  condition:
    any of them
}