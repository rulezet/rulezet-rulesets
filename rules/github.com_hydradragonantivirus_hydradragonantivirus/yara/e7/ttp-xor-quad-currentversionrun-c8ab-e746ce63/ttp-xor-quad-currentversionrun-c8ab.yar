rule TTP_XOR_QUAD_CurrentVersionRun_c8ab {
  strings:
    $key_c8ab = { 9b c4 [2] bf ca [2] 94 e6 [2] ba c4 [2] ae df [2] a1 c5 [2] bf d8 [2] bd d9 [2] a6 df [2] ba d8 [2] a6 f7 }

  condition:
    any of them
}