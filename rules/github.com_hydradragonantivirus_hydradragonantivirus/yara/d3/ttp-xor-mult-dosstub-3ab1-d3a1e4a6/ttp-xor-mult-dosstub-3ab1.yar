rule TTP_XOR_MULT_DOSStub_3ab1 {
  strings:
    $key_3ab1 = { 6e d9 [2] 1a c1 [2] 5d c3 [2] 1a d2 [2] 54 de [2] 58 d4 [2] 4f df [2] 54 91 [2] 69 }

  condition:
    any of them
}