rule TTP_XOR_QUAD_CurrentVersionRun_5aba {
  strings:
    $key_5aba = { 09 d5 [2] 2d db [2] 06 f7 [2] 28 d5 [2] 3c ce [2] 33 d4 [2] 2d c9 [2] 2f c8 [2] 34 ce [2] 28 c9 [2] 34 e6 }

  condition:
    any of them
}