rule TTP_XOR_QUAD_CurrentVersionRun_5aa5 {
  strings:
    $key_5aa5 = { 09 ca [2] 2d c4 [2] 06 e8 [2] 28 ca [2] 3c d1 [2] 33 cb [2] 2d d6 [2] 2f d7 [2] 34 d1 [2] 28 d6 [2] 34 f9 }

  condition:
    any of them
}