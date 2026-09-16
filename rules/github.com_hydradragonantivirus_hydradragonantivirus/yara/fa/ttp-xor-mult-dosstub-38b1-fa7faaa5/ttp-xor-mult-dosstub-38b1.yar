rule TTP_XOR_MULT_DOSStub_38b1 {
  strings:
    $key_38b1 = { 6c d9 [2] 18 c1 [2] 5f c3 [2] 18 d2 [2] 56 de [2] 5a d4 [2] 4d df [2] 56 91 [2] 6b }

  condition:
    any of them
}