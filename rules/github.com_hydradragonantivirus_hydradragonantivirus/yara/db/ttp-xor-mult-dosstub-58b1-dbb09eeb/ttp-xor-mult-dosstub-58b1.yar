rule TTP_XOR_MULT_DOSStub_58b1 {
  strings:
    $key_58b1 = { 0c d9 [2] 78 c1 [2] 3f c3 [2] 78 d2 [2] 36 de [2] 3a d4 [2] 2d df [2] 36 91 [2] 0b }

  condition:
    any of them
}