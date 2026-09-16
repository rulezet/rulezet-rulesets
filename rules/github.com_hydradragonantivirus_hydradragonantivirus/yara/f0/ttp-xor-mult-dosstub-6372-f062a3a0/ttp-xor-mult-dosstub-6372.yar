rule TTP_XOR_MULT_DOSStub_6372 {
  strings:
    $key_6372 = { 37 1a [2] 43 02 [2] 04 00 [2] 43 11 [2] 0d 1d [2] 01 17 [2] 16 1c [2] 0d 52 [2] 30 }

  condition:
    any of them
}