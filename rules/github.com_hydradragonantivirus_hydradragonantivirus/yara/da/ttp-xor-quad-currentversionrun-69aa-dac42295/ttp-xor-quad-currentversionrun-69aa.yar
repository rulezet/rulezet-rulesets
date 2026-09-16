rule TTP_XOR_QUAD_CurrentVersionRun_69aa {
  strings:
    $key_69aa = { 3a c5 [2] 1e cb [2] 35 e7 [2] 1b c5 [2] 0f de [2] 00 c4 [2] 1e d9 [2] 1c d8 [2] 07 de [2] 1b d9 [2] 07 f6 }

  condition:
    any of them
}