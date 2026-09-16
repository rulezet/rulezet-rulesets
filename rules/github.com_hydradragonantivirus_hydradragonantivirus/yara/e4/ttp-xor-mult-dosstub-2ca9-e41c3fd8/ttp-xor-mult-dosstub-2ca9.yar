rule TTP_XOR_MULT_DOSStub_2ca9 {
  strings:
    $key_2ca9 = { 78 c1 [2] 0c d9 [2] 4b db [2] 0c ca [2] 42 c6 [2] 4e cc [2] 59 c7 [2] 42 89 [2] 7f }

  condition:
    any of them
}