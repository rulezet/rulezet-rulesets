rule TTP_XOR_QUAD_CurrentVersionRun_49aa {
  strings:
    $key_49aa = { 1a c5 [2] 3e cb [2] 15 e7 [2] 3b c5 [2] 2f de [2] 20 c4 [2] 3e d9 [2] 3c d8 [2] 27 de [2] 3b d9 [2] 27 f6 }

  condition:
    any of them
}