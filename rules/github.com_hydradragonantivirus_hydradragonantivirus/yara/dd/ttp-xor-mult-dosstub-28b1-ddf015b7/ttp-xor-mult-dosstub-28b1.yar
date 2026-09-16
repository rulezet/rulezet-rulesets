rule TTP_XOR_MULT_DOSStub_28b1 {
  strings:
    $key_28b1 = { 7c d9 [2] 08 c1 [2] 4f c3 [2] 08 d2 [2] 46 de [2] 4a d4 [2] 5d df [2] 46 91 [2] 7b }

  condition:
    any of them
}