rule TTP_XOR_MULT_DOSStub_5454 {
  strings:
    $key_5454 = { 00 3c [2] 74 24 [2] 33 26 [2] 74 37 [2] 3a 3b [2] 36 31 [2] 21 3a [2] 3a 74 [2] 07 }

  condition:
    any of them
}