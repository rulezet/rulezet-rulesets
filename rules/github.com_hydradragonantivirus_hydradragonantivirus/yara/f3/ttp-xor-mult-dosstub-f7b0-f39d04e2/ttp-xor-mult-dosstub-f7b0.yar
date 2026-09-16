rule TTP_XOR_MULT_DOSStub_f7b0 {
  strings:
    $key_f7b0 = { a3 d8 [2] d7 c0 [2] 90 c2 [2] d7 d3 [2] 99 df [2] 95 d5 [2] 82 de [2] 99 90 [2] a4 }

  condition:
    any of them
}