rule TTP_XOR_QUAD_CurrentVersionRun_0ba4 {
  strings:
    $key_0ba4 = { 58 cb [2] 7c c5 [2] 57 e9 [2] 79 cb [2] 6d d0 [2] 62 ca [2] 7c d7 [2] 7e d6 [2] 65 d0 [2] 79 d7 [2] 65 f8 }

  condition:
    any of them
}