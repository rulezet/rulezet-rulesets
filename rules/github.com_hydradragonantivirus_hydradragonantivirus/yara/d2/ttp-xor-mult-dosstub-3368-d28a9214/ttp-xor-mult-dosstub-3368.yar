rule TTP_XOR_MULT_DOSStub_3368 {
  strings:
    $key_3368 = { 67 00 [2] 13 18 [2] 54 1a [2] 13 0b [2] 5d 07 [2] 51 0d [2] 46 06 [2] 5d 48 [2] 60 }

  condition:
    any of them
}