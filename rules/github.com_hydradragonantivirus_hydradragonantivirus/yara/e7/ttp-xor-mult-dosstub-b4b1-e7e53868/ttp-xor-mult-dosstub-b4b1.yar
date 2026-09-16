rule TTP_XOR_MULT_DOSStub_b4b1 {
  strings:
    $key_b4b1 = { e0 d9 [2] 94 c1 [2] d3 c3 [2] 94 d2 [2] da de [2] d6 d4 [2] c1 df [2] da 91 [2] e7 }

  condition:
    any of them
}