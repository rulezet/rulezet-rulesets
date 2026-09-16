rule TTP_XOR_MULT_DOSStub_8bb6 {
  strings:
    $key_8bb6 = { df de [2] ab c6 [2] ec c4 [2] ab d5 [2] e5 d9 [2] e9 d3 [2] fe d8 [2] e5 96 [2] d8 }

  condition:
    any of them
}