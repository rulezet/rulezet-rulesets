rule TTP_XOR_MULT_DOSStub_7349 {
  strings:
    $key_7349 = { 27 21 [2] 53 39 [2] 14 3b [2] 53 2a [2] 1d 26 [2] 11 2c [2] 06 27 [2] 1d 69 [2] 20 }

  condition:
    any of them
}