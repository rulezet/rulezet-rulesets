rule TTP_XOR_QUAD_CurrentVersionRun_6aa4 {
  strings:
    $key_6aa4 = { 39 cb [2] 1d c5 [2] 36 e9 [2] 18 cb [2] 0c d0 [2] 03 ca [2] 1d d7 [2] 1f d6 [2] 04 d0 [2] 18 d7 [2] 04 f8 }

  condition:
    any of them
}