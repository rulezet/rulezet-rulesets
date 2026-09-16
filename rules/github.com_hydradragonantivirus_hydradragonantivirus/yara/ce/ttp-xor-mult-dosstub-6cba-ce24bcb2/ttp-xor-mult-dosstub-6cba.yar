rule TTP_XOR_MULT_DOSStub_6cba {
  strings:
    $key_6cba = { 38 d2 [2] 4c ca [2] 0b c8 [2] 4c d9 [2] 02 d5 [2] 0e df [2] 19 d4 [2] 02 9a [2] 3f }

  condition:
    any of them
}