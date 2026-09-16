rule TTP_XOR_QUAD_CurrentVersionRun_50a5 {
  strings:
    $key_50a5 = { 03 ca [2] 27 c4 [2] 0c e8 [2] 22 ca [2] 36 d1 [2] 39 cb [2] 27 d6 [2] 25 d7 [2] 3e d1 [2] 22 d6 [2] 3e f9 }

  condition:
    any of them
}