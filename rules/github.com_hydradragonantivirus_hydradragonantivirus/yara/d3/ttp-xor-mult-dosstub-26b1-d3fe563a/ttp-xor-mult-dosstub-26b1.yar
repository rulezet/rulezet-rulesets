rule TTP_XOR_MULT_DOSStub_26b1 {
  strings:
    $key_26b1 = { 72 d9 [2] 06 c1 [2] 41 c3 [2] 06 d2 [2] 48 de [2] 44 d4 [2] 53 df [2] 48 91 [2] 75 }

  condition:
    any of them
}