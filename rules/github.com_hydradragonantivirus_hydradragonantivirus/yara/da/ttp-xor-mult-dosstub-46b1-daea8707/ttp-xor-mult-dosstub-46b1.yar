rule TTP_XOR_MULT_DOSStub_46b1 {
  strings:
    $key_46b1 = { 12 d9 [2] 66 c1 [2] 21 c3 [2] 66 d2 [2] 28 de [2] 24 d4 [2] 33 df [2] 28 91 [2] 15 }

  condition:
    any of them
}