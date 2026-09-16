rule TTP_XOR_MULT_DOSStub_0368 {
  strings:
    $key_0368 = { 57 00 [2] 23 18 [2] 64 1a [2] 23 0b [2] 6d 07 [2] 61 0d [2] 76 06 [2] 6d 48 [2] 50 }

  condition:
    any of them
}