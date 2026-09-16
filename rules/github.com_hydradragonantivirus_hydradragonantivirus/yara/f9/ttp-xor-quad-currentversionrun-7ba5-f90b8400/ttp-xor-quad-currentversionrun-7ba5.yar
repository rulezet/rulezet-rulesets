rule TTP_XOR_QUAD_CurrentVersionRun_7ba5 {
  strings:
    $key_7ba5 = { 28 ca [2] 0c c4 [2] 27 e8 [2] 09 ca [2] 1d d1 [2] 12 cb [2] 0c d6 [2] 0e d7 [2] 15 d1 [2] 09 d6 [2] 15 f9 }

  condition:
    any of them
}