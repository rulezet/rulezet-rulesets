rule TTP_XOR_QUAD_CurrentVersionRun_3eaa {
  strings:
    $key_3eaa = { 6d c5 [2] 49 cb [2] 62 e7 [2] 4c c5 [2] 58 de [2] 57 c4 [2] 49 d9 [2] 4b d8 [2] 50 de [2] 4c d9 [2] 50 f6 }

  condition:
    any of them
}