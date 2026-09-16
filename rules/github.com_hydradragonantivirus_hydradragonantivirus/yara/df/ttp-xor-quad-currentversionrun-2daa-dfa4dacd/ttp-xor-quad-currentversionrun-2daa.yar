rule TTP_XOR_QUAD_CurrentVersionRun_2daa {
  strings:
    $key_2daa = { 7e c5 [2] 5a cb [2] 71 e7 [2] 5f c5 [2] 4b de [2] 44 c4 [2] 5a d9 [2] 58 d8 [2] 43 de [2] 5f d9 [2] 43 f6 }

  condition:
    any of them
}