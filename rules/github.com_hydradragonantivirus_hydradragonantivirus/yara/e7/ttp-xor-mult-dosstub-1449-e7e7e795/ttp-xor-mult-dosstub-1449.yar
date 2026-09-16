rule TTP_XOR_MULT_DOSStub_1449 {
  strings:
    $key_1449 = { 40 21 [2] 34 39 [2] 73 3b [2] 34 2a [2] 7a 26 [2] 76 2c [2] 61 27 [2] 7a 69 [2] 47 }

  condition:
    any of them
}