rule TTP_XOR_MULT_DOSStub_1454 {
  strings:
    $key_1454 = { 40 3c [2] 34 24 [2] 73 26 [2] 34 37 [2] 7a 3b [2] 76 31 [2] 61 3a [2] 7a 74 [2] 47 }

  condition:
    any of them
}