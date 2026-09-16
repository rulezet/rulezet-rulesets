rule TTP_XOR_QUAD_CurrentVersionRun_60a4 {
  strings:
    $key_60a4 = { 33 cb [2] 17 c5 [2] 3c e9 [2] 12 cb [2] 06 d0 [2] 09 ca [2] 17 d7 [2] 15 d6 [2] 0e d0 [2] 12 d7 [2] 0e f8 }

  condition:
    any of them
}