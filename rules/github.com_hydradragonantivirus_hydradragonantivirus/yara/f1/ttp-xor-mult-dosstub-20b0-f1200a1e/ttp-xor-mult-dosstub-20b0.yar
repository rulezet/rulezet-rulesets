rule TTP_XOR_MULT_DOSStub_20b0 {
  strings:
    $key_20b0 = { 74 d8 [2] 00 c0 [2] 47 c2 [2] 00 d3 [2] 4e df [2] 42 d5 [2] 55 de [2] 4e 90 [2] 73 }

  condition:
    any of them
}