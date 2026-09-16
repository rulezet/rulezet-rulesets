rule TTP_XOR_MULT_DOSStub_4674 {
  strings:
    $key_4674 = { 12 1c [2] 66 04 [2] 21 06 [2] 66 17 [2] 28 1b [2] 24 11 [2] 33 1a [2] 28 54 [2] 15 }

  condition:
    any of them
}