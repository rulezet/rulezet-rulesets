rule TTP_XOR_MULT_DOSStub_3a34 {
  strings:
    $key_3a34 = { 6e 5c [2] 1a 44 [2] 5d 46 [2] 1a 57 [2] 54 5b [2] 58 51 [2] 4f 5a [2] 54 14 [2] 69 }

  condition:
    any of them
}