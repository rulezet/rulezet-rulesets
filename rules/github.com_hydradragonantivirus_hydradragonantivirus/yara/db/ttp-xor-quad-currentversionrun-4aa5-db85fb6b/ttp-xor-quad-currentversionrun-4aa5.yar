rule TTP_XOR_QUAD_CurrentVersionRun_4aa5 {
  strings:
    $key_4aa5 = { 19 ca [2] 3d c4 [2] 16 e8 [2] 38 ca [2] 2c d1 [2] 23 cb [2] 3d d6 [2] 3f d7 [2] 24 d1 [2] 38 d6 [2] 24 f9 }

  condition:
    any of them
}