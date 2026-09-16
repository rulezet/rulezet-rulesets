rule TTP_XOR_MULT_DOSStub_1768 {
  strings:
    $key_1768 = { 43 00 [2] 37 18 [2] 70 1a [2] 37 0b [2] 79 07 [2] 75 0d [2] 62 06 [2] 79 48 [2] 44 }

  condition:
    any of them
}