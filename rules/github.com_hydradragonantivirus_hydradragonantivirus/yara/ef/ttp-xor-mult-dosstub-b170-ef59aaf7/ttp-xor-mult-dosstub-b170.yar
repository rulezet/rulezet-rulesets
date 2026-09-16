rule TTP_XOR_MULT_DOSStub_b170 {
  strings:
    $key_b170 = { e5 18 [2] 91 00 [2] d6 02 [2] 91 13 [2] df 1f [2] d3 15 [2] c4 1e [2] df 50 [2] e2 }

  condition:
    any of them
}