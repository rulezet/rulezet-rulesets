rule TTP_XOR_QUAD_CurrentVersionRun_1daa {
  strings:
    $key_1daa = { 4e c5 [2] 6a cb [2] 41 e7 [2] 6f c5 [2] 7b de [2] 74 c4 [2] 6a d9 [2] 68 d8 [2] 73 de [2] 6f d9 [2] 73 f6 }

  condition:
    any of them
}