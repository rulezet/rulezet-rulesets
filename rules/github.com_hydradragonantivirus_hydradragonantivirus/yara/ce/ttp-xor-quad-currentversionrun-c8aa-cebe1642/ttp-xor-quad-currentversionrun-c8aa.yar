rule TTP_XOR_QUAD_CurrentVersionRun_c8aa {
  strings:
    $key_c8aa = { 9b c5 [2] bf cb [2] 94 e7 [2] ba c5 [2] ae de [2] a1 c4 [2] bf d9 [2] bd d8 [2] a6 de [2] ba d9 [2] a6 f6 }

  condition:
    any of them
}