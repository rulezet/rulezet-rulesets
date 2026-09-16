rule TTP_XOR_QUAD_CurrentVersionRun_fbaa {
  strings:
    $key_fbaa = { a8 c5 [2] 8c cb [2] a7 e7 [2] 89 c5 [2] 9d de [2] 92 c4 [2] 8c d9 [2] 8e d8 [2] 95 de [2] 89 d9 [2] 95 f6 }

  condition:
    any of them
}