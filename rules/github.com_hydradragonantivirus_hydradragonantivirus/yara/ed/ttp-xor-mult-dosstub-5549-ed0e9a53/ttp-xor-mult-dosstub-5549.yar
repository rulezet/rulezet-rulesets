rule TTP_XOR_MULT_DOSStub_5549 {
  strings:
    $key_5549 = { 01 21 [2] 75 39 [2] 32 3b [2] 75 2a [2] 3b 26 [2] 37 2c [2] 20 27 [2] 3b 69 [2] 06 }

  condition:
    any of them
}