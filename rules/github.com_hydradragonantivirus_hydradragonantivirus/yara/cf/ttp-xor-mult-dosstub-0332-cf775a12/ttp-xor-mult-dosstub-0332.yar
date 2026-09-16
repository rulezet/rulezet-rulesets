rule TTP_XOR_MULT_DOSStub_0332 {
  strings:
    $key_0332 = { 57 5a [2] 23 42 [2] 64 40 [2] 23 51 [2] 6d 5d [2] 61 57 [2] 76 5c [2] 6d 12 [2] 50 }

  condition:
    any of them
}