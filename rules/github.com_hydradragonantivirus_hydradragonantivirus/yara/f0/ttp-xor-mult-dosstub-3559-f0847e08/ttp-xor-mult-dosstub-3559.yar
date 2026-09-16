rule TTP_XOR_MULT_DOSStub_3559 {
  strings:
    $key_3559 = { 61 31 [2] 15 29 [2] 52 2b [2] 15 3a [2] 5b 36 [2] 57 3c [2] 40 37 [2] 5b 79 [2] 66 }

  condition:
    any of them
}