rule TTP_XOR_MULT_DOSStub_5465 {
  strings:
    $key_5465 = { 00 0d [2] 74 15 [2] 33 17 [2] 74 06 [2] 3a 0a [2] 36 00 [2] 21 0b [2] 3a 45 [2] 07 }

  condition:
    any of them
}