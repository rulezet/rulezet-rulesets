rule TTP_XOR_MULT_DOSStub_4549 {
  strings:
    $key_4549 = { 11 21 [2] 65 39 [2] 22 3b [2] 65 2a [2] 2b 26 [2] 27 2c [2] 30 27 [2] 2b 69 [2] 16 }

  condition:
    any of them
}