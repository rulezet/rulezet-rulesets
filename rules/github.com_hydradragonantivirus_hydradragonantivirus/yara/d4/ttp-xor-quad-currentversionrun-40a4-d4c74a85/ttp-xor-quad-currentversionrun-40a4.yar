rule TTP_XOR_QUAD_CurrentVersionRun_40a4 {
  strings:
    $key_40a4 = { 13 cb [2] 37 c5 [2] 1c e9 [2] 32 cb [2] 26 d0 [2] 29 ca [2] 37 d7 [2] 35 d6 [2] 2e d0 [2] 32 d7 [2] 2e f8 }

  condition:
    any of them
}