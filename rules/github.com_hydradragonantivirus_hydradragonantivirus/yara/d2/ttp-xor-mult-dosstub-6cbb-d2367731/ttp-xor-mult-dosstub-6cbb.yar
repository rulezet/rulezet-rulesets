rule TTP_XOR_MULT_DOSStub_6cbb {
  strings:
    $key_6cbb = { 38 d3 [2] 4c cb [2] 0b c9 [2] 4c d8 [2] 02 d4 [2] 0e de [2] 19 d5 [2] 02 9b [2] 3f }

  condition:
    any of them
}