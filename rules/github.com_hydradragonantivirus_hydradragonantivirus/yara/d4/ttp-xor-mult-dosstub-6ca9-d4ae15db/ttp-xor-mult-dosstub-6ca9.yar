rule TTP_XOR_MULT_DOSStub_6ca9 {
  strings:
    $key_6ca9 = { 38 c1 [2] 4c d9 [2] 0b db [2] 4c ca [2] 02 c6 [2] 0e cc [2] 19 c7 [2] 02 89 [2] 3f }

  condition:
    any of them
}