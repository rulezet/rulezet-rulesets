rule TTP_XOR_QUAD_CurrentVersionRun_1cba {
  strings:
    $key_1cba = { 4f d5 [2] 6b db [2] 40 f7 [2] 6e d5 [2] 7a ce [2] 75 d4 [2] 6b c9 [2] 69 c8 [2] 72 ce [2] 6e c9 [2] 72 e6 }

  condition:
    any of them
}