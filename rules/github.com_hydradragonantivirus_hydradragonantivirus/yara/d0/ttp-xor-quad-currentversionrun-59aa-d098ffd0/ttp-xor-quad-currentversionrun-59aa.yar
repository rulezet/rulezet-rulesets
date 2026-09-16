rule TTP_XOR_QUAD_CurrentVersionRun_59aa {
  strings:
    $key_59aa = { 0a c5 [2] 2e cb [2] 05 e7 [2] 2b c5 [2] 3f de [2] 30 c4 [2] 2e d9 [2] 2c d8 [2] 37 de [2] 2b d9 [2] 37 f6 }

  condition:
    any of them
}