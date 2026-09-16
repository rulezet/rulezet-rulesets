rule TTP_XOR_MULT_DOSStub_1368 {
  strings:
    $key_1368 = { 47 00 [2] 33 18 [2] 74 1a [2] 33 0b [2] 7d 07 [2] 71 0d [2] 66 06 [2] 7d 48 [2] 40 }

  condition:
    any of them
}