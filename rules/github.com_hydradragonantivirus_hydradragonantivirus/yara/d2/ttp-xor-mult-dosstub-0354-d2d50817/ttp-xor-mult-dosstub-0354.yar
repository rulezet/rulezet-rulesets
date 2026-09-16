rule TTP_XOR_MULT_DOSStub_0354 {
  strings:
    $key_0354 = { 57 3c [2] 23 24 [2] 64 26 [2] 23 37 [2] 6d 3b [2] 61 31 [2] 76 3a [2] 6d 74 [2] 50 }

  condition:
    any of them
}