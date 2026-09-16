rule TTP_XOR_QUAD_CurrentVersionRun_4daa {
  strings:
    $key_4daa = { 1e c5 [2] 3a cb [2] 11 e7 [2] 3f c5 [2] 2b de [2] 24 c4 [2] 3a d9 [2] 38 d8 [2] 23 de [2] 3f d9 [2] 23 f6 }

  condition:
    any of them
}