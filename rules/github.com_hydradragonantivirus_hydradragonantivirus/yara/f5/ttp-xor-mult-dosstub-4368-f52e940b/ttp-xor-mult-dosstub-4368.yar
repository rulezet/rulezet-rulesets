rule TTP_XOR_MULT_DOSStub_4368 {
  strings:
    $key_4368 = { 17 00 [2] 63 18 [2] 24 1a [2] 63 0b [2] 2d 07 [2] 21 0d [2] 36 06 [2] 2d 48 [2] 10 }

  condition:
    any of them
}