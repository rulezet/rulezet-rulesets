rule TTP_XOR_QUAD_CurrentVersionRun_f9aa {
  strings:
    $key_f9aa = { aa c5 [2] 8e cb [2] a5 e7 [2] 8b c5 [2] 9f de [2] 90 c4 [2] 8e d9 [2] 8c d8 [2] 97 de [2] 8b d9 [2] 97 f6 }

  condition:
    any of them
}