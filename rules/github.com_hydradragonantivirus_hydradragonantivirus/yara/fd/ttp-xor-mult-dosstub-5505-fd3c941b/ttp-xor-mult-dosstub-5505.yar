rule TTP_XOR_MULT_DOSStub_5505 {
  strings:
    $key_5505 = { 01 6d [2] 75 75 [2] 32 77 [2] 75 66 [2] 3b 6a [2] 37 60 [2] 20 6b [2] 3b 25 [2] 06 }

  condition:
    any of them
}