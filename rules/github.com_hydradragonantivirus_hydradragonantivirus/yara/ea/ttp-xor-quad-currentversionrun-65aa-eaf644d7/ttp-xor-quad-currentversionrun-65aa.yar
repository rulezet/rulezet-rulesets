rule TTP_XOR_QUAD_CurrentVersionRun_65aa {
  strings:
    $key_65aa = { 36 c5 [2] 12 cb [2] 39 e7 [2] 17 c5 [2] 03 de [2] 0c c4 [2] 12 d9 [2] 10 d8 [2] 0b de [2] 17 d9 [2] 0b f6 }

  condition:
    any of them
}