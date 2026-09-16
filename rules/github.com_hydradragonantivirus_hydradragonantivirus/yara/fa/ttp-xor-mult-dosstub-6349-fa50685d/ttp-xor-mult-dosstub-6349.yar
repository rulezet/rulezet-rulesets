rule TTP_XOR_MULT_DOSStub_6349 {
  strings:
    $key_6349 = { 37 21 [2] 43 39 [2] 04 3b [2] 43 2a [2] 0d 26 [2] 01 2c [2] 16 27 [2] 0d 69 [2] 30 }

  condition:
    any of them
}