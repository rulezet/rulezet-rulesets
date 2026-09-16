rule TTP_XOR_QUAD_CurrentVersionRun_0baa {
  strings:
    $key_0baa = { 58 c5 [2] 7c cb [2] 57 e7 [2] 79 c5 [2] 6d de [2] 62 c4 [2] 7c d9 [2] 7e d8 [2] 65 de [2] 79 d9 [2] 65 f6 }

  condition:
    any of them
}