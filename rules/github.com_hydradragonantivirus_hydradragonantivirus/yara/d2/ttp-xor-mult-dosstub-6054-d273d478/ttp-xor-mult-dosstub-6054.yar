rule TTP_XOR_MULT_DOSStub_6054 {
  strings:
    $key_6054 = { 34 3c [2] 40 24 [2] 07 26 [2] 40 37 [2] 0e 3b [2] 02 31 [2] 15 3a [2] 0e 74 [2] 33 }

  condition:
    any of them
}