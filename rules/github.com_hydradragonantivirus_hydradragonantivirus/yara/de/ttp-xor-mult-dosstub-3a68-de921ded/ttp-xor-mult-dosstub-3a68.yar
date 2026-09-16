rule TTP_XOR_MULT_DOSStub_3a68 {
  strings:
    $key_3a68 = { 6e 00 [2] 1a 18 [2] 5d 1a [2] 1a 0b [2] 54 07 [2] 58 0d [2] 4f 06 [2] 54 48 [2] 69 }

  condition:
    any of them
}