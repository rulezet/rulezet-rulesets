rule TTP_XOR_MULT_DOSStub_5149 {
  strings:
    $key_5149 = { 05 21 [2] 71 39 [2] 36 3b [2] 71 2a [2] 3f 26 [2] 33 2c [2] 24 27 [2] 3f 69 [2] 02 }

  condition:
    any of them
}