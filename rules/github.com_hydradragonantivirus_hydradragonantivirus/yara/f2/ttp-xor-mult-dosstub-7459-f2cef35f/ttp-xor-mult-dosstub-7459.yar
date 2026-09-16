rule TTP_XOR_MULT_DOSStub_7459 {
  strings:
    $key_7459 = { 20 31 [2] 54 29 [2] 13 2b [2] 54 3a [2] 1a 36 [2] 16 3c [2] 01 37 [2] 1a 79 [2] 27 }

  condition:
    any of them
}