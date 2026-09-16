rule TTP_XOR_MULT_DOSStub_4432 {
  strings:
    $key_4432 = { 10 5a [2] 64 42 [2] 23 40 [2] 64 51 [2] 2a 5d [2] 26 57 [2] 31 5c [2] 2a 12 [2] 17 }

  condition:
    any of them
}