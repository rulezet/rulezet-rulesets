rule TTP_XOR_MULT_DOSStub_3a04 {
  strings:
    $key_3a04 = { 6e 6c [2] 1a 74 [2] 5d 76 [2] 1a 67 [2] 54 6b [2] 58 61 [2] 4f 6a [2] 54 24 [2] 69 }

  condition:
    any of them
}