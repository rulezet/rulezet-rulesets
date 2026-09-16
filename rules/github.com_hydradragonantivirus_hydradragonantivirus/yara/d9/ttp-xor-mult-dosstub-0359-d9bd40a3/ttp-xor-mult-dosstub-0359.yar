rule TTP_XOR_MULT_DOSStub_0359 {
  strings:
    $key_0359 = { 57 31 [2] 23 29 [2] 64 2b [2] 23 3a [2] 6d 36 [2] 61 3c [2] 76 37 [2] 6d 79 [2] 50 }

  condition:
    any of them
}