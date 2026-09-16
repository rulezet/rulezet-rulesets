rule TTP_XOR_MULT_DOSStub_1772 {
  strings:
    $key_1772 = { 43 1a [2] 37 02 [2] 70 00 [2] 37 11 [2] 79 1d [2] 75 17 [2] 62 1c [2] 79 52 [2] 44 }

  condition:
    any of them
}