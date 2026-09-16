rule TTP_XOR_MULT_DOSStub_4405 {
  strings:
    $key_4405 = { 10 6d [2] 64 75 [2] 23 77 [2] 64 66 [2] 2a 6a [2] 26 60 [2] 31 6b [2] 2a 25 [2] 17 }

  condition:
    any of them
}