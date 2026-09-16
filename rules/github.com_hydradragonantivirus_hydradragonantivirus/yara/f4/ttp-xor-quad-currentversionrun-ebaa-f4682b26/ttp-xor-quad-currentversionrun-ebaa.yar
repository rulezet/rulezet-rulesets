rule TTP_XOR_QUAD_CurrentVersionRun_ebaa {
  strings:
    $key_ebaa = { b8 c5 [2] 9c cb [2] b7 e7 [2] 99 c5 [2] 8d de [2] 82 c4 [2] 9c d9 [2] 9e d8 [2] 85 de [2] 99 d9 [2] 85 f6 }

  condition:
    any of them
}