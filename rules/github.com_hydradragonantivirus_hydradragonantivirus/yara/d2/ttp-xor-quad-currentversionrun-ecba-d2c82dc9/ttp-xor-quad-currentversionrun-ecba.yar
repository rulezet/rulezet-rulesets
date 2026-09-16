rule TTP_XOR_QUAD_CurrentVersionRun_ecba {
  strings:
    $key_ecba = { bf d5 [2] 9b db [2] b0 f7 [2] 9e d5 [2] 8a ce [2] 85 d4 [2] 9b c9 [2] 99 c8 [2] 82 ce [2] 9e c9 [2] 82 e6 }

  condition:
    any of them
}