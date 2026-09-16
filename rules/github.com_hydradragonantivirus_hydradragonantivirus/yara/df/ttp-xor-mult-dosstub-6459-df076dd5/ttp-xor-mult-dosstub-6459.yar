rule TTP_XOR_MULT_DOSStub_6459 {
  strings:
    $key_6459 = { 30 31 [2] 44 29 [2] 03 2b [2] 44 3a [2] 0a 36 [2] 06 3c [2] 11 37 [2] 0a 79 [2] 37 }

  condition:
    any of them
}