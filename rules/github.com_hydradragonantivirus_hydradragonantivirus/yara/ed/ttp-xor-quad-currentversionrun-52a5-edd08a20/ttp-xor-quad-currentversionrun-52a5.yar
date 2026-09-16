rule TTP_XOR_QUAD_CurrentVersionRun_52a5 {
  strings:
    $key_52a5 = { 01 ca [2] 25 c4 [2] 0e e8 [2] 20 ca [2] 34 d1 [2] 3b cb [2] 25 d6 [2] 27 d7 [2] 3c d1 [2] 20 d6 [2] 3c f9 }

  condition:
    any of them
}