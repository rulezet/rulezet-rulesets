rule TTP_XOR_QUAD_CurrentVersionRun_7eaa {
  strings:
    $key_7eaa = { 2d c5 [2] 09 cb [2] 22 e7 [2] 0c c5 [2] 18 de [2] 17 c4 [2] 09 d9 [2] 0b d8 [2] 10 de [2] 0c d9 [2] 10 f6 }

  condition:
    any of them
}