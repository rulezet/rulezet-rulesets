rule TTP_XOR_QUAD_CurrentVersionRun_52a4 {
  strings:
    $key_52a4 = { 01 cb [2] 25 c5 [2] 0e e9 [2] 20 cb [2] 34 d0 [2] 3b ca [2] 25 d7 [2] 27 d6 [2] 3c d0 [2] 20 d7 [2] 3c f8 }

  condition:
    any of them
}