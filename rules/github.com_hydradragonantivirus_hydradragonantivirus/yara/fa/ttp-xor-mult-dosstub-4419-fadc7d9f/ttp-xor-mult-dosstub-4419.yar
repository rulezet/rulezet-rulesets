rule TTP_XOR_MULT_DOSStub_4419 {
  strings:
    $key_4419 = { 10 71 [2] 64 69 [2] 23 6b [2] 64 7a [2] 2a 76 [2] 26 7c [2] 31 77 [2] 2a 39 [2] 17 }

  condition:
    any of them
}