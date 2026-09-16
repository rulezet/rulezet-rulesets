rule TTP_XOR_QUAD_CurrentVersionRun_42b6 {
  strings:
    $key_42b6 = { 11 d9 [2] 35 d7 [2] 1e fb [2] 30 d9 [2] 24 c2 [2] 2b d8 [2] 35 c5 [2] 37 c4 [2] 2c c2 [2] 30 c5 [2] 2c ea }

  condition:
    any of them
}