rule TTP_XOR_MULT_DOSStub_08b1 {
  strings:
    $key_08b1 = { 5c d9 [2] 28 c1 [2] 6f c3 [2] 28 d2 [2] 66 de [2] 6a d4 [2] 7d df [2] 66 91 [2] 5b }

  condition:
    any of them
}