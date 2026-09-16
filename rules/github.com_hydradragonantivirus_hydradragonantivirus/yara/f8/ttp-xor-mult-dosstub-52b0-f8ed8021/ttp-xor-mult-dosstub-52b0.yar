rule TTP_XOR_MULT_DOSStub_52b0 {
  strings:
    $key_52b0 = { 06 d8 [2] 72 c0 [2] 35 c2 [2] 72 d3 [2] 3c df [2] 30 d5 [2] 27 de [2] 3c 90 [2] 01 }

  condition:
    any of them
}