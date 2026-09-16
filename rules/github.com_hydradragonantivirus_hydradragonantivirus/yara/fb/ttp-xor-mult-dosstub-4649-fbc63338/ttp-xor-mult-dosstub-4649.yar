rule TTP_XOR_MULT_DOSStub_4649 {
  strings:
    $key_4649 = { 12 21 [2] 66 39 [2] 21 3b [2] 66 2a [2] 28 26 [2] 24 2c [2] 33 27 [2] 28 69 [2] 15 }

  condition:
    any of them
}