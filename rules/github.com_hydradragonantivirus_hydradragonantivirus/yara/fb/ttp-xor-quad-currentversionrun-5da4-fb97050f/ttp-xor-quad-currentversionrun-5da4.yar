rule TTP_XOR_QUAD_CurrentVersionRun_5da4 {
  strings:
    $key_5da4 = { 0e cb [2] 2a c5 [2] 01 e9 [2] 2f cb [2] 3b d0 [2] 34 ca [2] 2a d7 [2] 28 d6 [2] 33 d0 [2] 2f d7 [2] 33 f8 }

  condition:
    any of them
}