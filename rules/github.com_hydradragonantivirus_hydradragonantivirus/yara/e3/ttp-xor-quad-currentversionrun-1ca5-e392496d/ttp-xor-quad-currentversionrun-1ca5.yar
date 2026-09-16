rule TTP_XOR_QUAD_CurrentVersionRun_1ca5 {
  strings:
    $key_1ca5 = { 4f ca [2] 6b c4 [2] 40 e8 [2] 6e ca [2] 7a d1 [2] 75 cb [2] 6b d6 [2] 69 d7 [2] 72 d1 [2] 6e d6 [2] 72 f9 }

  condition:
    any of them
}