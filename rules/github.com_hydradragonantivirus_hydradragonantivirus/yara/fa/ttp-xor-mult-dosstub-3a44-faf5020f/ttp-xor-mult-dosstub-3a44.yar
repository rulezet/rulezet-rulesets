rule TTP_XOR_MULT_DOSStub_3a44 {
  strings:
    $key_3a44 = { 6e 2c [2] 1a 34 [2] 5d 36 [2] 1a 27 [2] 54 2b [2] 58 21 [2] 4f 2a [2] 54 64 [2] 69 }

  condition:
    any of them
}