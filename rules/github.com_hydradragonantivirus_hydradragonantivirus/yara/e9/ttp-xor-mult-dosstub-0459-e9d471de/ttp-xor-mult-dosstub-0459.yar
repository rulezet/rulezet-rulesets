rule TTP_XOR_MULT_DOSStub_0459 {
  strings:
    $key_0459 = { 50 31 [2] 24 29 [2] 63 2b [2] 24 3a [2] 6a 36 [2] 66 3c [2] 71 37 [2] 6a 79 [2] 57 }

  condition:
    any of them
}