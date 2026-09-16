rule TTP_XOR_QUAD_CurrentVersionRun_e9aa {
  strings:
    $key_e9aa = { ba c5 [2] 9e cb [2] b5 e7 [2] 9b c5 [2] 8f de [2] 80 c4 [2] 9e d9 [2] 9c d8 [2] 87 de [2] 9b d9 [2] 87 f6 }

  condition:
    any of them
}