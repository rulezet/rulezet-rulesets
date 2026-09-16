rule TTP_XOR_QUAD_CurrentVersionRun_4ba5 {
  strings:
    $key_4ba5 = { 18 ca [2] 3c c4 [2] 17 e8 [2] 39 ca [2] 2d d1 [2] 22 cb [2] 3c d6 [2] 3e d7 [2] 25 d1 [2] 39 d6 [2] 25 f9 }

  condition:
    any of them
}