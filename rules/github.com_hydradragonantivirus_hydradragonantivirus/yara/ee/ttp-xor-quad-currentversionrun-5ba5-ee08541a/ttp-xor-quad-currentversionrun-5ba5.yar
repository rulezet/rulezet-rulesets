rule TTP_XOR_QUAD_CurrentVersionRun_5ba5 {
  strings:
    $key_5ba5 = { 08 ca [2] 2c c4 [2] 07 e8 [2] 29 ca [2] 3d d1 [2] 32 cb [2] 2c d6 [2] 2e d7 [2] 35 d1 [2] 29 d6 [2] 35 f9 }

  condition:
    any of them
}