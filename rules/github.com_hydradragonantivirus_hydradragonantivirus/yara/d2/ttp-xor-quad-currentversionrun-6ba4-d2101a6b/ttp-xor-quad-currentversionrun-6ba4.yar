rule TTP_XOR_QUAD_CurrentVersionRun_6ba4 {
  strings:
    $key_6ba4 = { 38 cb [2] 1c c5 [2] 37 e9 [2] 19 cb [2] 0d d0 [2] 02 ca [2] 1c d7 [2] 1e d6 [2] 05 d0 [2] 19 d7 [2] 05 f8 }

  condition:
    any of them
}