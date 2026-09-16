rule TTP_XOR_MULT_DOSStub_4554 {
  strings:
    $key_4554 = { 11 3c [2] 65 24 [2] 22 26 [2] 65 37 [2] 2b 3b [2] 27 31 [2] 30 3a [2] 2b 74 [2] 16 }

  condition:
    any of them
}