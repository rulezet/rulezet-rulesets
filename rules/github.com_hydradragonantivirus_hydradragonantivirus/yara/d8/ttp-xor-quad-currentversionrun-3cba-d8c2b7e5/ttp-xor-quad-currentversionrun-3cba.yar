rule TTP_XOR_QUAD_CurrentVersionRun_3cba {
  strings:
    $key_3cba = { 6f d5 [2] 4b db [2] 60 f7 [2] 4e d5 [2] 5a ce [2] 55 d4 [2] 4b c9 [2] 49 c8 [2] 52 ce [2] 4e c9 [2] 52 e6 }

  condition:
    any of them
}