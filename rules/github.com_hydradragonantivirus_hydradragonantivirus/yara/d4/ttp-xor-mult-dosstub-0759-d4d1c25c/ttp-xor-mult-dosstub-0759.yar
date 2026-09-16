rule TTP_XOR_MULT_DOSStub_0759 {
  strings:
    $key_0759 = { 53 31 [2] 27 29 [2] 60 2b [2] 27 3a [2] 69 36 [2] 65 3c [2] 72 37 [2] 69 79 [2] 54 }

  condition:
    any of them
}