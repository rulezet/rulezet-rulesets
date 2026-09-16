rule TTP_XOR_MULT_DOSStub_37b6 {
  strings:
    $key_37b6 = { 63 de [2] 17 c6 [2] 50 c4 [2] 17 d5 [2] 59 d9 [2] 55 d3 [2] 42 d8 [2] 59 96 [2] 64 }

  condition:
    any of them
}