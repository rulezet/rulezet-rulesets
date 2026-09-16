rule TTP_XOR_MULT_DOSStub_2cbb {
  strings:
    $key_2cbb = { 78 d3 [2] 0c cb [2] 4b c9 [2] 0c d8 [2] 42 d4 [2] 4e de [2] 59 d5 [2] 42 9b [2] 7f }

  condition:
    any of them
}