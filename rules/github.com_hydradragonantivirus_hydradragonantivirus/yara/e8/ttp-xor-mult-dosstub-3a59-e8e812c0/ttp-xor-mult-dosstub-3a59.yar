rule TTP_XOR_MULT_DOSStub_3a59 {
  strings:
    $key_3a59 = { 6e 31 [2] 1a 29 [2] 5d 2b [2] 1a 3a [2] 54 36 [2] 58 3c [2] 4f 37 [2] 54 79 [2] 69 }

  condition:
    any of them
}