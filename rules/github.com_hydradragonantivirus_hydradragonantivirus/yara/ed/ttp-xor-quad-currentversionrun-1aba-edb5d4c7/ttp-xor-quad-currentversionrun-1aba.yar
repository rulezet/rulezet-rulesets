rule TTP_XOR_QUAD_CurrentVersionRun_1aba {
  strings:
    $key_1aba = { 49 d5 [2] 6d db [2] 46 f7 [2] 68 d5 [2] 7c ce [2] 73 d4 [2] 6d c9 [2] 6f c8 [2] 74 ce [2] 68 c9 [2] 74 e6 }

  condition:
    any of them
}