rule TTP_XOR_MULT_DOSStub_1472 {
  strings:
    $key_1472 = { 40 1a [2] 34 02 [2] 73 00 [2] 34 11 [2] 7a 1d [2] 76 17 [2] 61 1c [2] 7a 52 [2] 47 }

  condition:
    any of them
}