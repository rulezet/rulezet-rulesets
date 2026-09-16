rule TTP_XOR_QUAD_CurrentVersionRun_79aa {
  strings:
    $key_79aa = { 2a c5 [2] 0e cb [2] 25 e7 [2] 0b c5 [2] 1f de [2] 10 c4 [2] 0e d9 [2] 0c d8 [2] 17 de [2] 0b d9 [2] 17 f6 }

  condition:
    any of them
}