rule TTP_XOR_MULT_DOSStub_f2b0 {
  strings:
    $key_f2b0 = { a6 d8 [2] d2 c0 [2] 95 c2 [2] d2 d3 [2] 9c df [2] 90 d5 [2] 87 de [2] 9c 90 [2] a1 }

  condition:
    any of them
}