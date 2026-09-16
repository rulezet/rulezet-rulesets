rule TTP_XOR_QUAD_CurrentVersionRun_70a4 {
  strings:
    $key_70a4 = { 23 cb [2] 07 c5 [2] 2c e9 [2] 02 cb [2] 16 d0 [2] 19 ca [2] 07 d7 [2] 05 d6 [2] 1e d0 [2] 02 d7 [2] 1e f8 }

  condition:
    any of them
}