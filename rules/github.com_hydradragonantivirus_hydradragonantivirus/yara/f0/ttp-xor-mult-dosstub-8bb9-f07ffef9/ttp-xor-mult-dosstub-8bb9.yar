rule TTP_XOR_MULT_DOSStub_8bb9 {
  strings:
    $key_8bb9 = { df d1 [2] ab c9 [2] ec cb [2] ab da [2] e5 d6 [2] e9 dc [2] fe d7 [2] e5 99 [2] d8 }

  condition:
    any of them
}