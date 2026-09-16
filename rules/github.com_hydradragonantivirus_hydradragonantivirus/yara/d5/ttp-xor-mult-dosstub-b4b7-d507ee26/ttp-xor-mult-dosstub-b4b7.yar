rule TTP_XOR_MULT_DOSStub_b4b7 {
  strings:
    $key_b4b7 = { e0 df [2] 94 c7 [2] d3 c5 [2] 94 d4 [2] da d8 [2] d6 d2 [2] c1 d9 [2] da 97 [2] e7 }

  condition:
    any of them
}