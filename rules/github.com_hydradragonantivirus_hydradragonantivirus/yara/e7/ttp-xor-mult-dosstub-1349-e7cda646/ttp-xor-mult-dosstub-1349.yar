rule TTP_XOR_MULT_DOSStub_1349 {
  strings:
    $key_1349 = { 47 21 [2] 33 39 [2] 74 3b [2] 33 2a [2] 7d 26 [2] 71 2c [2] 66 27 [2] 7d 69 [2] 40 }

  condition:
    any of them
}