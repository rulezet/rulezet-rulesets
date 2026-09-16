rule TTP_XOR_QUAD_CurrentVersionRun_f2aa {
  strings:
    $key_f2aa = { a1 c5 [2] 85 cb [2] ae e7 [2] 80 c5 [2] 94 de [2] 9b c4 [2] 85 d9 [2] 87 d8 [2] 9c de [2] 80 d9 [2] 9c f6 }

  condition:
    any of them
}